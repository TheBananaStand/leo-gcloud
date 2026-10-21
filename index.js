#!/usr/bin/env node
//
// Google Cloud as Leo tools, over MCP.
//
// TWO TOOLS, read and state-changing, kept apart so the second one is the only
// thing that can move anything:
//
//   gcloud        — projects, VMs, Cloud Run, buckets, objects, Cloud SQL,
//                   GKE, functions, logs, billing. Read-only, every one.
//   gcloud_admin  — start, stop or reset a Compute Engine VM. Nothing here
//                   deletes, and nothing here creates.
//
// AUTH IS A SERVICE ACCOUNT, NOT THE USER'S GOOGLE LOGIN.
//
// Leo's `google` OAuth provider carries Gmail/Drive/Calendar scopes and not
// `cloud-platform`, so borrowing it would mean re-consenting every household
// member to a scope none of them asked for — and a person's own Google account
// is usually not the identity that owns the infrastructure anyway. So this
// package takes a service-account key from its own settings and mints its own
// access tokens:
//
//   signed JWT (RS256, the key's private half)
//     -> POST https://oauth2.googleapis.com/token
//        grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//     -> {"access_token": "...", "expires_in": 3599}
//
// The key never leaves this process; what travels to Google is a one-hour
// assertion signed with it. The token is cached in memory until a minute before
// it expires, so a run of ten tool calls is one token request.
//
// Grant the service account `roles/viewer` and it can answer everything the
// read tool asks. `gcloud_admin` additionally needs
// `roles/compute.instanceAdmin.v1` — withhold that role and the admin tool
// fails at Google with a legible permission error, which is a perfectly good
// way to run this package read-only.
//
// Plain JavaScript on purpose: this ships as a git tarball, and npm does not
// reliably run build steps for a tarball URL.

import { readFile } from "node:fs/promises";
import { createSign } from "node:crypto";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

/** Settings key holding the service-account key JSON (or a path to it). */
export const CREDENTIAL_SETTING = "gcloud_service_account_json";
/** Settings key holding the project every action defaults to. */
export const PROJECT_SETTING = "gcloud_project_id";

const TOKEN_URL = "https://oauth2.googleapis.com/token";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/** One scope. The service account's IAM roles are the real limit. */
const SCOPE = "https://www.googleapis.com/auth/cloud-platform";

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const RESOURCE_MANAGER = "https://cloudresourcemanager.googleapis.com/v1";
const RUN = "https://run.googleapis.com/v2";
const STORAGE = "https://storage.googleapis.com/storage/v1";
const SQLADMIN = "https://sqladmin.googleapis.com/sql/v1beta4";
const CONTAINER = "https://container.googleapis.com/v1";
const FUNCTIONS = "https://cloudfunctions.googleapis.com/v2";
const LOGGING = "https://logging.googleapis.com/v2";
const BILLING = "https://cloudbilling.googleapis.com/v1";

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/**
 * Turn whatever the owner pasted into a usable service-account key.
 *
 * Three shapes arrive here and only one of them is the documented one:
 *
 * - the key JSON itself, pasted whole;
 * - a *path* to the key on the hub, which is what a box that already had
 *   `GOOGLE_APPLICATION_CREDENTIALS` set will hand over;
 * - key JSON whose `private_key` newlines have been escaped to a literal `\n`,
 *   which is what happens when someone round-trips the file through a shell
 *   variable or a JSON string field. OpenSSL rejects that PEM with "no start
 *   line", an error that says nothing about the real cause — so it is repaired
 *   here rather than diagnosed later.
 *
 * A `gcloud auth login` credential (`type: authorized_user`) is refused by
 * name: it looks like a key, is in the same directory as one, and can never
 * sign an assertion.
 */
export function parseCredential(raw) {
  const text = (raw ?? "").trim();
  if (!text) throw new Error(missingCredentialMessage());

  let sa;
  try {
    sa = JSON.parse(text);
  } catch {
    throw new Error(
      `${CREDENTIAL_SETTING} is neither JSON nor a readable file path. Paste the ` +
        "service-account key JSON, or the path to it on the hub.",
    );
  }

  if (sa.type === "authorized_user") {
    throw new Error(
      "That is a `gcloud auth login` user credential, not a service-account key. " +
        "Create a key under IAM & Admin → Service Accounts → Keys → Add key (JSON).",
    );
  }
  for (const field of ["client_email", "private_key"]) {
    if (typeof sa[field] !== "string" || sa[field] === "") {
      throw new Error(`${CREDENTIAL_SETTING} has no \`${field}\` — that is not a service-account key.`);
    }
  }
  // A real PEM has real newlines; a round-tripped one has the two characters
  // `\` and `n` instead. Unescaping is safe either way — a PEM contains no
  // other backslash for this to damage.
  sa.private_key = sa.private_key.replace(/\\n/g, "\n");
  return sa;
}

function missingCredentialMessage() {
  return (
    `No ${CREDENTIAL_SETTING} configured. Add a service-account key in ` +
    "Settings → Packages → Google Cloud (the JSON from IAM & Admin → Service " +
    "Accounts → Keys, or a path to it on the hub)."
  );
}

/** Read the credential from settings, falling back to the Google SDK's env var. */
async function loadCredential() {
  const raw = (process.env[CREDENTIAL_SETTING] ?? "").trim();
  const source = raw || (process.env.GOOGLE_APPLICATION_CREDENTIALS ?? "").trim();
  if (!source) throw new Error(missingCredentialMessage());
  // A path is anything that isn't the JSON itself. Read it here so the
  // not-found error names the file instead of the setting.
  if (!source.startsWith("{")) {
    let text;
    try {
      text = await readFile(source, "utf8");
    } catch (e) {
      throw new Error(`Could not read the service-account key at ${source}: ${e.code ?? e.message}`);
    }
    return parseCredential(text);
  }
  return parseCredential(source);
}

// ---------------------------------------------------------------------------
// Access tokens
// ---------------------------------------------------------------------------

/**
 * The signed assertion Google exchanges for an access token.
 *
 * Exported because it is the one piece of this file that can be wrong in a way
 * no HTTP error explains: a bad claim set comes back as `invalid_grant`, which
 * reads identically to a revoked key.
 */
export function assertionFor(sa, { now = Math.floor(Date.now() / 1000), scope = SCOPE } = {}) {
  const header = { alg: "RS256", typ: "JWT" };
  if (sa.private_key_id) header.kid = sa.private_key_id;
  const claims = {
    iss: sa.client_email,
    scope,
    aud: sa.token_uri || TOKEN_URL,
    iat: now,
    // Google's ceiling is one hour; anything longer is rejected outright.
    exp: now + 3600,
  };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const signingInput = `${b64(header)}.${b64(claims)}`;
  const signature = createSign("RSA-SHA256").update(signingInput).sign(sa.private_key);
  return `${signingInput}.${signature.toString("base64url")}`;
}

/** Cached token, so a multi-call turn pays for one exchange. */
let tokenCache = null;

export function cachedToken(cache, { client_email }, now = Date.now()) {
  if (!cache || cache.client_email !== client_email) return null;
  // A minute of slack: a token that expires mid-request is a 401 the model
  // reports as a permission problem.
  return cache.expires_at - 60_000 > now ? cache.access_token : null;
}

async function getAccessToken() {
  const sa = await loadCredential();
  const hit = cachedToken(tokenCache, sa);
  if (hit) return { token: hit, sa };

  const body = new URLSearchParams({
    grant_type: JWT_BEARER,
    assertion: assertionFor(sa),
  });
  const resp = await fetch(sa.token_uri || TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const payload = await resp.json().catch(() => ({}));
  if (!resp.ok || !payload.access_token) {
    throw new Error(tokenErrorMessage(resp.status, payload, sa));
  }
  tokenCache = {
    client_email: sa.client_email,
    access_token: payload.access_token,
    expires_at: Date.now() + (Number(payload.expires_in) || 3600) * 1000,
  };
  return { token: payload.access_token, sa };
}

/**
 * Say which of the three token failures happened.
 *
 * `invalid_grant` is the one worth naming: it is what a deleted key, a deleted
 * service account and a clock skewed past the assertion window all return, and
 * none of those is "wrong password".
 */
export function tokenErrorMessage(status, payload, sa) {
  const code = payload?.error ?? `HTTP ${status}`;
  const detail = payload?.error_description ?? "";
  if (code === "invalid_grant") {
    return (
      `Google refused the service-account key for ${sa.client_email} (invalid_grant: ${detail}). ` +
      "The key or the service account has probably been deleted — or this box's clock is wrong."
    );
  }
  if (code === "invalid_client") {
    return `Google does not recognise ${sa.client_email} (invalid_client: ${detail}).`;
  }
  return `Token request failed (${code}${detail ? `: ${detail}` : ""}).`;
}

// ---------------------------------------------------------------------------
// Calling the APIs
// ---------------------------------------------------------------------------

/**
 * Turn a Google API error body into one sentence a person can act on.
 *
 * The 403 that matters is a *disabled API*, not a missing role: the project is
 * fine, the credential is fine, and someone has to click Enable. Google says so
 * in prose inside `error.message`, so the console link is attached here where
 * the project id is still in hand.
 */
export function apiErrorMessage(status, payload, { project } = {}) {
  const message = payload?.error?.message ?? payload?.error_description ?? `HTTP ${status}`;
  if (/has not been used in project|SERVICE_DISABLED/i.test(message)) {
    const where = project ? `?project=${encodeURIComponent(project)}` : "";
    return `${message} Enable it at https://console.cloud.google.com/apis/library${where}`;
  }
  if (status === 403) {
    return `${message} (the service account needs a role that grants this — roles/viewer covers every read action.)`;
  }
  return message;
}

async function call(token, url, { method = "GET", body, project } = {}) {
  const resp = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const payload = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(apiErrorMessage(resp.status, payload, { project }));
  return payload;
}

// ---------------------------------------------------------------------------
// Pure helpers — what this server can get wrong without anyone noticing,
// because a Google API error is loud and a mis-shaped answer is not.
// ---------------------------------------------------------------------------

/** The project an action runs against: the call's, else the setting's, else the key's. */
export function projectFor(args, sa, env = process.env) {
  const project =
    (args?.project ?? "").trim() || (env[PROJECT_SETTING] ?? "").trim() || (sa?.project_id ?? "");
  if (!project) {
    throw new Error(
      `No project. Pass \`project\`, or set ${PROJECT_SETTING} in Settings → Packages → Google Cloud.`,
    );
  }
  return project;
}

export function clampLimit(value, fallback, max) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), max);
}

/** The last path segment of a resource URL — `…/zones/us-central1-a` → `us-central1-a`. */
export function basename(url) {
  return typeof url === "string" ? url.split("/").filter(Boolean).pop() ?? "" : "";
}

/**
 * Flatten `compute.instances.aggregatedList`, whose payload is a map of
 * `zones/<zone>` to either a list of instances or a `warning` saying there are
 * none. Reading the warning branch as instances is how an aggregated list
 * quietly becomes a list of `undefined`.
 */
export function shapeInstances(payload, limit = Infinity) {
  const out = [];
  for (const bucket of Object.values(payload?.items ?? {})) {
    for (const vm of bucket?.instances ?? []) {
      if (out.length >= limit) return out;
      out.push({
        name: vm.name,
        zone: basename(vm.zone),
        status: vm.status,
        machine_type: basename(vm.machineType),
        internal_ip: vm.networkInterfaces?.[0]?.networkIP ?? null,
        external_ip: vm.networkInterfaces?.[0]?.accessConfigs?.[0]?.natIP ?? null,
        created: vm.creationTimestamp ?? null,
      });
    }
  }
  return out;
}

/**
 * Find the zone a VM lives in, so the model can say "stop the build box"
 * without knowing where it runs.
 *
 * An ambiguous name is an error rather than a guess: two projects' worth of
 * naming conventions make `web-1` in two zones entirely ordinary, and stopping
 * the wrong one is not recoverable by retrying.
 */
export function findZoneForInstance(payload, name) {
  const matches = shapeInstances(payload).filter((vm) => vm.name === name);
  if (matches.length === 0) {
    throw new Error(`No instance named ${name} in this project.`);
  }
  if (matches.length > 1) {
    throw new Error(
      `${name} exists in ${matches.length} zones (${matches.map((m) => m.zone).join(", ")}) — pass \`zone\`.`,
    );
  }
  return matches[0].zone;
}

export function shapeRunServices(payload) {
  return (payload?.services ?? []).map((s) => ({
    name: basename(s.name),
    region: s.name?.split("/locations/")[1]?.split("/")[0] ?? null,
    url: s.uri ?? null,
    image: s.template?.containers?.[0]?.image ?? null,
    last_modifier: s.lastModifier ?? null,
    updated: s.updateTime ?? null,
    ready: s.terminalCondition?.type === "Ready" ? s.terminalCondition.state : null,
  }));
}

export function shapeBuckets(payload) {
  return (payload?.items ?? []).map((b) => ({
    name: b.name,
    location: b.location,
    storage_class: b.storageClass,
    created: b.timeCreated,
    public_access_prevention: b.iamConfiguration?.publicAccessPrevention ?? null,
  }));
}

export function shapeObjects(payload) {
  return (payload?.items ?? []).map((o) => ({
    name: o.name,
    size_bytes: Number(o.size ?? 0),
    content_type: o.contentType ?? null,
    updated: o.updated,
  }));
}

export function shapeSqlInstances(payload) {
  return (payload?.items ?? []).map((i) => ({
    name: i.name,
    state: i.state,
    database_version: i.databaseVersion,
    tier: i.settings?.tier ?? null,
    region: i.region,
    public_ip: (i.ipAddresses ?? []).find((a) => a.type === "PRIMARY")?.ipAddress ?? null,
  }));
}

export function shapeClusters(payload) {
  return (payload?.clusters ?? []).map((c) => ({
    name: c.name,
    location: c.location,
    status: c.status,
    version: c.currentMasterVersion,
    nodes: c.currentNodeCount ?? null,
  }));
}

export function shapeFunctions(payload) {
  return (payload?.functions ?? []).map((f) => ({
    name: basename(f.name),
    state: f.state,
    runtime: f.buildConfig?.runtime ?? null,
    entry_point: f.buildConfig?.entryPoint ?? null,
    url: f.serviceConfig?.uri ?? null,
    updated: f.updateTime ?? null,
  }));
}

/**
 * Keep the parts of a log entry a reader needs and drop the rest.
 *
 * A raw `entries.list` page is mostly envelope — resource labels, insert ids,
 * trace ids — and a hundred of those is a context window spent on nothing. The
 * payload lives under one of three different keys depending on how the entry
 * was written, which is the detail that makes a naive reader show empty lines
 * for every structured log in the project.
 */
export function shapeLogEntries(payload) {
  return (payload?.entries ?? []).map((e) => ({
    timestamp: e.timestamp,
    severity: e.severity ?? "DEFAULT",
    resource: e.resource?.type ?? null,
    log: basename(e.logName),
    message:
      e.textPayload ??
      e.jsonPayload?.message ??
      (e.jsonPayload ? JSON.stringify(e.jsonPayload) : null) ??
      e.protoPayload?.methodName ??
      null,
  }));
}

export function shapeBilling(payload) {
  return {
    project: basename(payload?.name?.replace("/billingInfo", "") ?? ""),
    billing_account: payload?.billingAccountName ?? null,
    billing_enabled: payload?.billingEnabled ?? false,
  };
}

// ---------------------------------------------------------------------------
// gcloud (read) actions
// ---------------------------------------------------------------------------

async function actionProjects(token, args) {
  const limit = clampLimit(args.limit, 50, 200);
  const payload = await call(token, `${RESOURCE_MANAGER}/projects?pageSize=${limit}`);
  return (payload.projects ?? [])
    .filter((p) => p.lifecycleState === "ACTIVE")
    .map((p) => ({
      project_id: p.projectId,
      name: p.name,
      number: p.projectNumber,
      created: p.createTime,
    }));
}

async function instancePage(token, project, limit) {
  // `maxResults` on an aggregated list is per zone, not overall — the cap that
  // matters is applied while flattening.
  return call(
    token,
    `${COMPUTE}/projects/${encodeURIComponent(project)}/aggregated/instances?maxResults=${limit}`,
    { project },
  );
}

async function actionInstances(token, project, args) {
  const limit = clampLimit(args.limit, 50, 200);
  return shapeInstances(await instancePage(token, project, limit), limit);
}

async function actionRunServices(token, project, args) {
  const region = (args.region ?? "-").trim() || "-";
  const payload = await call(
    token,
    `${RUN}/projects/${encodeURIComponent(project)}/locations/${encodeURIComponent(region)}/services`,
    { project },
  );
  return shapeRunServices(payload);
}

async function actionBuckets(token, project, args) {
  const limit = clampLimit(args.limit, 50, 200);
  const payload = await call(
    token,
    `${STORAGE}/b?project=${encodeURIComponent(project)}&maxResults=${limit}`,
    { project },
  );
  return shapeBuckets(payload);
}

async function actionObjects(token, project, args) {
  if (!args.bucket) throw new Error("`bucket` is required for the objects action.");
  const limit = clampLimit(args.limit, 50, 500);
  const prefix = args.prefix ? `&prefix=${encodeURIComponent(args.prefix)}` : "";
  const payload = await call(
    token,
    `${STORAGE}/b/${encodeURIComponent(args.bucket)}/o?maxResults=${limit}${prefix}`,
    { project },
  );
  return shapeObjects(payload);
}

async function actionSqlInstances(token, project) {
  return shapeSqlInstances(
    await call(token, `${SQLADMIN}/projects/${encodeURIComponent(project)}/instances`, { project }),
  );
}

async function actionClusters(token, project) {
  return shapeClusters(
    await call(token, `${CONTAINER}/projects/${encodeURIComponent(project)}/locations/-/clusters`, {
      project,
    }),
  );
}

async function actionFunctions(token, project) {
  return shapeFunctions(
    await call(token, `${FUNCTIONS}/projects/${encodeURIComponent(project)}/locations/-/functions`, {
      project,
    }),
  );
}

async function actionLogs(token, project, args) {
  const limit = clampLimit(args.limit, 25, 200);
  const filter = (args.filter ?? "").trim();
  const since = (args.since ?? "1h").trim();
  // Always bounded in time. An unfiltered `entries.list` walks the whole
  // retention window oldest-first and times out on a busy project; a freshness
  // clause is what makes "what just broke" a cheap question.
  const freshness = `timestamp >= "${sinceTimestamp(since)}"`;
  const payload = await call(token, `${LOGGING}/entries:list`, {
    method: "POST",
    project,
    body: {
      resourceNames: [`projects/${project}`],
      filter: filter ? `${freshness} AND (${filter})` : freshness,
      orderBy: "timestamp desc",
      pageSize: limit,
    },
  });
  return shapeLogEntries(payload);
}

/**
 * Turn `15m` / `2h` / `3d` into an RFC-3339 instant.
 *
 * Accepts an explicit timestamp unchanged, so a caller who knows the window can
 * say so. An unparseable value falls back to an hour rather than to no bound:
 * the failure mode of a silently unbounded log query is a timeout, not an
 * error, and it costs the project real money on a big log bucket.
 */
export function sinceTimestamp(since, now = Date.now()) {
  if (/^\d{4}-\d{2}-\d{2}T/.test(since)) return since;
  const m = /^(\d+)\s*([mhd])$/.exec(since.trim());
  const units = { m: 60_000, h: 3_600_000, d: 86_400_000 };
  const ms = m ? Number(m[1]) * units[m[2]] : 3_600_000;
  return new Date(now - ms).toISOString();
}

async function actionBilling(token, project) {
  return shapeBilling(
    await call(token, `${BILLING}/projects/${encodeURIComponent(project)}/billingInfo`, { project }),
  );
}

// ---------------------------------------------------------------------------
// gcloud_admin actions
// ---------------------------------------------------------------------------

const LIFECYCLE = { instance_start: "start", instance_stop: "stop", instance_reset: "reset" };

async function instanceLifecycle(token, project, args, verb) {
  if (!args.instance) throw new Error(`\`instance\` is required for ${args.action}.`);
  const zone =
    (args.zone ?? "").trim() ||
    findZoneForInstance(await instancePage(token, project, 200), args.instance);
  const payload = await call(
    token,
    `${COMPUTE}/projects/${encodeURIComponent(project)}/zones/${encodeURIComponent(zone)}` +
      `/instances/${encodeURIComponent(args.instance)}/${verb}`,
    { method: "POST", project },
  );
  // Compute returns an Operation, not the instance — so the honest answer is
  // "accepted", with where to look. Reporting the instance as stopped here
  // would be a guess about something that takes ~30 seconds.
  return {
    accepted: true,
    operation: payload.name ?? null,
    instance: args.instance,
    zone,
    requested: verb,
    note: "Compute applies this asynchronously — re-run `gcloud` with action=instances to see the new status.",
  };
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

const READ_ACTIONS = [
  "projects",
  "instances",
  "run_services",
  "buckets",
  "objects",
  "sql_instances",
  "gke_clusters",
  "functions",
  "logs",
  "billing",
];

const TOOLS = {
  gcloud: {
    description:
      "Read Google Cloud state: projects, Compute Engine VMs, Cloud Run services, Storage buckets and objects, Cloud SQL instances, GKE clusters, Cloud Functions, log entries, and billing status. Read-only. Defaults to the configured project; pass `project` to look at another one.",
    inputSchema: {
      type: "object",
      properties: {
        action: { type: "string", enum: READ_ACTIONS, description: "What to read." },
        project: {
          type: "string",
          description: "Project id. Defaults to the configured project, else the service account's own.",
        },
        region: {
          type: "string",
          description: "For run_services: a region such as us-central1. Default `-` (all regions).",
        },
        bucket: { type: "string", description: "For objects: the bucket name." },
        prefix: { type: "string", description: "For objects: only names starting with this." },
        filter: {
          type: "string",
          description:
            'For logs: a Cloud Logging filter, e.g. severity>=ERROR or resource.type="cloud_run_revision". Combined with the time window.',
        },
        since: {
          type: "string",
          description: "For logs: how far back — 15m, 2h, 3d, or an RFC-3339 timestamp. Default 1h.",
        },
        limit: { type: "integer", description: "Max rows (default 50, logs 25)." },
      },
      required: ["action"],
    },
    run: async (args) => {
      const { token, sa } = await getAccessToken();
      if (args.action === "projects") return actionProjects(token, args);
      const project = projectFor(args, sa);
      switch (args.action) {
        case "instances":
          return actionInstances(token, project, args);
        case "run_services":
          return actionRunServices(token, project, args);
        case "buckets":
          return actionBuckets(token, project, args);
        case "objects":
          return actionObjects(token, project, args);
        case "sql_instances":
          return actionSqlInstances(token, project);
        case "gke_clusters":
          return actionClusters(token, project);
        case "functions":
          return actionFunctions(token, project);
        case "logs":
          return actionLogs(token, project, args);
        case "billing":
          return actionBilling(token, project);
        default:
          throw new Error(`Unknown action: ${args.action}. Use: ${READ_ACTIONS.join(", ")}`);
      }
    },
  },

  gcloud_admin: {
    description:
      "Change the run state of a Compute Engine VM: start, stop, or reset (hard reboot). Nothing here creates or deletes anything. If `zone` is omitted it is looked up from the instance name, and an ambiguous name is refused rather than guessed.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: Object.keys(LIFECYCLE),
          description: "instance_start, instance_stop, or instance_reset.",
        },
        instance: { type: "string", description: "Instance name." },
        zone: { type: "string", description: "Zone, e.g. us-central1-a. Looked up if omitted." },
        project: { type: "string", description: "Project id. Defaults to the configured project." },
      },
      required: ["action", "instance"],
    },
    run: async (args) => {
      const verb = LIFECYCLE[args.action];
      if (!verb) {
        throw new Error(`Unknown action: ${args.action}. Use: ${Object.keys(LIFECYCLE).join(", ")}`);
      }
      const { token, sa } = await getAccessToken();
      return instanceLifecycle(token, projectFor(args, sa), args, verb);
    },
  },
};

/** The tools/list payload — exported so a test can read it without a transport. */
export function toolList() {
  return Object.entries(TOOLS).map(([name, t]) => ({
    name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
}

export function missingRequired(name, args) {
  const required = TOOLS[name]?.inputSchema?.required ?? [];
  return required.filter((k) => {
    const v = args?.[k];
    return v === undefined || v === null || v === "";
  });
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

const server = new Server(
  { name: "leo-gcloud", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList() }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const tool = TOOLS[name];
  if (!tool) {
    return { isError: true, content: [{ type: "text", text: `Unknown tool: ${name}` }] };
  }
  const missing = missingRequired(name, args);
  if (missing.length > 0) {
    return {
      isError: true,
      content: [{ type: "text", text: `${name} requires: ${missing.join(", ")}` }],
    };
  }
  try {
    const answer = await tool.run(args ?? {});
    return {
      content: [
        { type: "text", text: typeof answer === "string" ? answer : JSON.stringify(answer, null, 2) },
      ],
    };
  } catch (error) {
    // `isError` is what the hub reads to tell "no VMs in this project" from
    // "the call did not run" — without it a missing credential records as a
    // successful empty result, and the model reports an empty cloud.
    return { isError: true, content: [{ type: "text", text: String(error?.message ?? error) }] };
  }
});

if (process.env.LEO_GCLOUD_NO_SERVE !== "1") {
  await server.connect(new StdioServerTransport());
}
