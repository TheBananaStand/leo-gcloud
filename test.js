// Smoke test — everything that can be checked without a Google project.
//
// The shaping and the assertion are what this server gets wrong silently: a
// Google API error is loud, a mis-read payload is not, and a malformed JWT
// comes back as `invalid_grant` which reads exactly like a revoked key. So the
// payload fixtures below are real response shapes, trimmed.
//
// `LEO_GCLOUD_NO_SERVE=1` keeps the import from attaching a stdio transport.
process.env.LEO_GCLOUD_NO_SERVE = "1";

import assert from "node:assert/strict";
import { generateKeyPairSync, createVerify } from "node:crypto";

import {
  CREDENTIAL_SETTING,
  PROJECT_SETTING,
  apiErrorMessage,
  assertionFor,
  basename,
  cachedToken,
  clampLimit,
  findZoneForInstance,
  missingRequired,
  parseCredential,
  projectFor,
  shapeBilling,
  shapeBuckets,
  shapeClusters,
  shapeFunctions,
  shapeInstances,
  shapeLogEntries,
  shapeObjects,
  shapeRunServices,
  shapeSqlInstances,
  sinceTimestamp,
  toolList,
  tokenErrorMessage,
} from "./index.js";

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL ${name}\n     ${e.message}`);
  }
}

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" });
const SA = {
  type: "service_account",
  project_id: "key-project",
  private_key_id: "kid-1",
  private_key: PEM,
  client_email: "leo@key-project.iam.gserviceaccount.com",
};

// --- credentials -----------------------------------------------------------

check("parses a service-account key", () => {
  const sa = parseCredential(JSON.stringify(SA));
  assert.equal(sa.client_email, SA.client_email);
  assert.ok(sa.private_key.includes("-----BEGIN"));
});

check("repairs a private key whose newlines were escaped", () => {
  const escaped = { ...SA, private_key: PEM.replace(/\n/g, "\\n") };
  const sa = parseCredential(JSON.stringify(escaped));
  assert.equal(sa.private_key, PEM);
  // And it still signs — the whole point of the repair.
  assert.ok(assertionFor(sa).split(".").length === 3);
});

check("refuses a gcloud user credential by name", () => {
  assert.throws(
    () => parseCredential(JSON.stringify({ type: "authorized_user", client_id: "x" })),
    /service-account key/,
  );
});

check("an empty credential names the setting", () => {
  assert.throws(() => parseCredential(""), new RegExp(CREDENTIAL_SETTING));
});

check("a key with no private half is refused", () => {
  assert.throws(
    () => parseCredential(JSON.stringify({ type: "service_account", client_email: "a@b" })),
    /private_key/,
  );
});

// --- the assertion ---------------------------------------------------------

check("the assertion is signed by the key and claims one hour", () => {
  const now = 1_760_000_000;
  const jwt = assertionFor(SA, { now });
  const [h, c, s] = jwt.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const claims = JSON.parse(Buffer.from(c, "base64url"));

  assert.deepEqual(header, { alg: "RS256", typ: "JWT", kid: "kid-1" });
  assert.equal(claims.iss, SA.client_email);
  assert.equal(claims.aud, "https://oauth2.googleapis.com/token");
  assert.equal(claims.scope, "https://www.googleapis.com/auth/cloud-platform");
  assert.equal(claims.iat, now);
  // Google rejects anything past an hour outright.
  assert.equal(claims.exp - claims.iat, 3600);

  const verified = createVerify("RSA-SHA256")
    .update(`${h}.${c}`)
    .verify(publicKey, Buffer.from(s, "base64url"));
  assert.ok(verified, "signature does not verify against the key's public half");
});

check("a cached token is reused until a minute before it expires", () => {
  const cache = { client_email: SA.client_email, access_token: "tok", expires_at: 10_000_000 };
  assert.equal(cachedToken(cache, SA, 10_000_000 - 120_000), "tok");
  assert.equal(cachedToken(cache, SA, 10_000_000 - 30_000), null, "expiring token was reused");
  assert.equal(cachedToken(cache, { client_email: "other@x" }, 0), null, "cache crossed accounts");
  assert.equal(cachedToken(null, SA), null);
});

check("invalid_grant is explained, not echoed", () => {
  const msg = tokenErrorMessage(400, { error: "invalid_grant", error_description: "bad" }, SA);
  assert.match(msg, /deleted/);
  assert.match(msg, new RegExp(SA.client_email));
});

// --- errors ----------------------------------------------------------------

check("a disabled API carries the console link", () => {
  const msg = apiErrorMessage(
    403,
    { error: { message: "Compute Engine API has not been used in project 123 before or it is disabled." } },
    { project: "p-1" },
  );
  assert.match(msg, /console\.cloud\.google\.com\/apis\/library\?project=p-1/);
});

check("a plain 403 names the role, not the API", () => {
  const msg = apiErrorMessage(403, { error: { message: "Permission denied." } }, { project: "p" });
  assert.match(msg, /roles\/viewer/);
  assert.doesNotMatch(msg, /apis\/library/);
});

// --- project resolution ----------------------------------------------------

check("project comes from the call, then the setting, then the key", () => {
  assert.equal(projectFor({ project: "from-call" }, SA, {}), "from-call");
  assert.equal(projectFor({}, SA, { [PROJECT_SETTING]: "from-setting" }), "from-setting");
  assert.equal(projectFor({}, SA, {}), "key-project");
  assert.throws(() => projectFor({}, {}, {}), new RegExp(PROJECT_SETTING));
  // Whitespace is not a project.
  assert.equal(projectFor({ project: "  " }, SA, {}), "key-project");
});

// --- shaping ---------------------------------------------------------------

const AGGREGATED = {
  items: {
    "zones/us-central1-a": {
      instances: [
        {
          name: "build-box",
          zone: "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
          status: "RUNNING",
          machineType: "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/machineTypes/e2-medium",
          creationTimestamp: "2026-01-02T03:04:05.000-08:00",
          networkInterfaces: [{ networkIP: "10.0.0.2", accessConfigs: [{ natIP: "34.1.2.3" }] }],
        },
      ],
    },
    // The branch that makes an aggregated list a list of `undefined` if read naively.
    "zones/europe-west1-b": {
      warning: { code: "NO_RESULTS_ON_PAGE", message: "There are no results for scope …" },
    },
    "zones/us-west1-a": {
      instances: [
        { name: "build-box", zone: "…/zones/us-west1-a", status: "TERMINATED", networkInterfaces: [] },
      ],
    },
  },
};

check("an aggregated instance list flattens, skipping empty-zone warnings", () => {
  const vms = shapeInstances(AGGREGATED);
  assert.equal(vms.length, 2);
  assert.deepEqual(vms[0], {
    name: "build-box",
    zone: "us-central1-a",
    status: "RUNNING",
    machine_type: "e2-medium",
    internal_ip: "10.0.0.2",
    external_ip: "34.1.2.3",
    created: "2026-01-02T03:04:05.000-08:00",
  });
  // A VM with no NIC has no IPs rather than throwing.
  assert.equal(vms[1].external_ip, null);
  assert.equal(shapeInstances(AGGREGATED, 1).length, 1, "limit not applied while flattening");
  assert.deepEqual(shapeInstances({}), []);
});

check("an ambiguous instance name is refused instead of guessed", () => {
  assert.throws(() => findZoneForInstance(AGGREGATED, "build-box"), /2 zones/);
  assert.throws(() => findZoneForInstance(AGGREGATED, "nope"), /No instance named nope/);
  const single = { items: { "zones/us-central1-a": AGGREGATED.items["zones/us-central1-a"] } };
  assert.equal(findZoneForInstance(single, "build-box"), "us-central1-a");
});

check("cloud run services keep their region and image", () => {
  const rows = shapeRunServices({
    services: [
      {
        name: "projects/p/locations/us-central1/services/api",
        uri: "https://api-abc.a.run.app",
        template: { containers: [{ image: "gcr.io/p/api:v3" }] },
        terminalCondition: { type: "Ready", state: "CONDITION_SUCCEEDED" },
        updateTime: "2026-10-01T00:00:00Z",
        lastModifier: "deploy@p.iam.gserviceaccount.com",
      },
    ],
  });
  assert.deepEqual(rows[0], {
    name: "api",
    region: "us-central1",
    url: "https://api-abc.a.run.app",
    image: "gcr.io/p/api:v3",
    last_modifier: "deploy@p.iam.gserviceaccount.com",
    updated: "2026-10-01T00:00:00Z",
    ready: "CONDITION_SUCCEEDED",
  });
  assert.deepEqual(shapeRunServices({}), []);
});

check("buckets, objects, sql, clusters and functions all shape empty payloads", () => {
  assert.deepEqual(shapeBuckets({}), []);
  assert.deepEqual(shapeObjects({}), []);
  assert.deepEqual(shapeSqlInstances({}), []);
  assert.deepEqual(shapeClusters({}), []);
  assert.deepEqual(shapeFunctions({}), []);
});

check("a bucket keeps its public-access posture", () => {
  const rows = shapeBuckets({
    items: [
      {
        name: "p-assets",
        location: "US",
        storageClass: "STANDARD",
        timeCreated: "2025-05-05T00:00:00Z",
        iamConfiguration: { publicAccessPrevention: "enforced" },
      },
    ],
  });
  assert.equal(rows[0].public_access_prevention, "enforced");
});

check("an object's size comes back as a number", () => {
  // GCS reports size as a *string*; arithmetic on it silently concatenates.
  const rows = shapeObjects({ items: [{ name: "a.bin", size: "1048576", updated: "x" }] });
  assert.equal(rows[0].size_bytes, 1048576);
});

check("a cloud sql instance keeps its primary IP only", () => {
  const rows = shapeSqlInstances({
    items: [
      {
        name: "db",
        state: "RUNNABLE",
        databaseVersion: "POSTGRES_15",
        region: "us-central1",
        settings: { tier: "db-g1-small" },
        ipAddresses: [
          { type: "OUTGOING", ipAddress: "9.9.9.9" },
          { type: "PRIMARY", ipAddress: "35.1.1.1" },
        ],
      },
    ],
  });
  assert.equal(rows[0].public_ip, "35.1.1.1");
});

check("a log entry's message is found wherever it was written", () => {
  const rows = shapeLogEntries({
    entries: [
      { timestamp: "t1", severity: "ERROR", logName: "projects/p/logs/stderr", textPayload: "boom" },
      { timestamp: "t2", logName: "projects/p/logs/run", jsonPayload: { message: "structured" } },
      { timestamp: "t3", logName: "projects/p/logs/x", jsonPayload: { code: 7 } },
      {
        timestamp: "t4",
        logName: "projects/p/logs/activity",
        protoPayload: { methodName: "v1.compute.instances.stop" },
      },
      { timestamp: "t5", logName: "projects/p/logs/empty" },
    ],
  });
  assert.deepEqual(
    rows.map((r) => r.message),
    ["boom", "structured", '{"code":7}', "v1.compute.instances.stop", null],
  );
  assert.equal(rows[0].log, "stderr");
  // An entry with no severity is DEFAULT, not undefined.
  assert.equal(rows[1].severity, "DEFAULT");
});

check("billing reports whether it is actually enabled", () => {
  const info = shapeBilling({
    name: "projects/p-1/billingInfo",
    billingAccountName: "billingAccounts/01-ABC",
    billingEnabled: true,
  });
  assert.deepEqual(info, {
    project: "p-1",
    billing_account: "billingAccounts/01-ABC",
    billing_enabled: true,
  });
  // A project with no billing says so rather than claiming it is on.
  assert.equal(shapeBilling({}).billing_enabled, false);
});

// --- small helpers ---------------------------------------------------------

check("limits are clamped, never trusted", () => {
  assert.equal(clampLimit(undefined, 50, 200), 50);
  assert.equal(clampLimit(1000, 50, 200), 200);
  assert.equal(clampLimit(0, 50, 200), 50);
  assert.equal(clampLimit(-3, 50, 200), 50);
  assert.equal(clampLimit("12", 50, 200), 12);
  assert.equal(clampLimit(7.9, 50, 200), 7);
});

check("basename survives a non-string", () => {
  assert.equal(basename(undefined), "");
  assert.equal(basename("a/b/c"), "c");
  assert.equal(basename("a/b/c/"), "c");
});

check("a log window is always bounded", () => {
  const now = Date.parse("2026-10-20T12:00:00.000Z");
  assert.equal(sinceTimestamp("15m", now), "2026-10-20T11:45:00.000Z");
  assert.equal(sinceTimestamp("2h", now), "2026-10-20T10:00:00.000Z");
  assert.equal(sinceTimestamp("3d", now), "2026-10-17T12:00:00.000Z");
  assert.equal(sinceTimestamp("2026-01-01T00:00:00Z", now), "2026-01-01T00:00:00Z");
  // Garbage falls back to an hour rather than to no bound at all.
  assert.equal(sinceTimestamp("whenever", now), "2026-10-20T11:00:00.000Z");
});

// --- the tool surface ------------------------------------------------------

check("both tools are advertised with an action enum", () => {
  const tools = toolList();
  assert.deepEqual(
    tools.map((t) => t.name),
    ["gcloud", "gcloud_admin"],
  );
  for (const t of tools) {
    assert.ok(t.description.length > 40, `${t.name} needs a real description`);
    assert.ok(t.inputSchema.properties.action.enum.length > 0);
    assert.ok(t.inputSchema.required.includes("action"));
  }
  // The read tool must not advertise anything that changes state.
  const read = tools[0].inputSchema.properties.action.enum;
  assert.ok(!read.some((a) => /start|stop|reset|delete|create/.test(a)), "read tool offers a mutation");
  assert.deepEqual(tools[1].inputSchema.properties.action.enum, [
    "instance_start",
    "instance_stop",
    "instance_reset",
  ]);
});

check("a missing required argument is named before any network call", () => {
  assert.deepEqual(missingRequired("gcloud", {}), ["action"]);
  assert.deepEqual(missingRequired("gcloud_admin", { action: "instance_stop" }), ["instance"]);
  assert.deepEqual(missingRequired("gcloud_admin", { action: "instance_stop", instance: "a" }), []);
  assert.deepEqual(missingRequired("nope", {}), []);
});

console.log(failures === 0 ? "\nall good" : `\n${failures} failing`);
process.exit(failures === 0 ? 0 : 1);
