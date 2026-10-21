# leo-gcloud

Google Cloud as [Leo](https://github.com/TheBananaStand) tools, over MCP.

Install it from Leo's Store (**Settings → Packages → Store → Google Cloud**), paste a
service-account key, and the agent can answer "what's running in prod", "show me the last
hour of errors from the API", "is billing still attached to that project" — and stop the
build box when you're done with it.

## Tools

### `gcloud` — read-only

| action | answers |
|---|---|
| `projects` | Active projects this service account can see |
| `instances` | Compute Engine VMs across every zone: status, machine type, IPs |
| `run_services` | Cloud Run services: URL, image, ready state (`region`, default all) |
| `buckets` | Storage buckets: location, class, public-access posture |
| `objects` | Object names, sizes and types in one `bucket` (optional `prefix`) |
| `sql_instances` | Cloud SQL instances: state, version, tier, primary IP |
| `gke_clusters` | GKE clusters: location, status, master version, node count |
| `functions` | Cloud Functions: state, runtime, entry point, URL |
| `logs` | Log entries, newest first — `filter` (Cloud Logging syntax), `since` (`15m`, `2h`, `3d`, or a timestamp; default `1h`) |
| `billing` | Which billing account the project is on, and whether billing is enabled |

Every action takes an optional `project` and `limit`. Object *contents* are never read —
only names and metadata.

### `gcloud_admin` — changes a VM's run state

`instance_start`, `instance_stop`, `instance_reset`, each taking `instance` and an
optional `zone`. Omit the zone and it is looked up from the name; a name that exists in
two zones is refused rather than guessed. Nothing here creates or deletes anything.

Compute applies these asynchronously, so the answer is "accepted" plus the operation name
— re-run `gcloud` with `action=instances` to see the new status.

## Settings

| key | what |
|---|---|
| `gcloud_service_account_json` | The service-account key JSON, pasted whole — or a path to it on the hub. Required. |
| `gcloud_project_id` | The project every action defaults to. Optional; falls back to the key's own `project_id`. |

`GOOGLE_APPLICATION_CREDENTIALS` is read as a fallback, so a box that already has a key on
disk needs no setting at all.

### Making the key

1. **IAM & Admin → Service Accounts → Create service account** (or pick an existing one).
2. Grant it **`roles/viewer`** on the project — that covers every read action.
   For `gcloud_admin`, also grant **`roles/compute.instanceAdmin.v1`**. Withhold that one
   and the admin tool fails at Google with a permission error, which is a perfectly good
   way to run this package read-only.
3. **Keys → Add key → JSON**, then paste the file's contents into the setting.

The APIs you want must be enabled on the project (Compute Engine, Cloud Run, Cloud SQL
Admin, Kubernetes Engine, Cloud Functions, Cloud Logging, Cloud Billing). A disabled API
comes back as an error naming it, with the console link to switch it on.

## How it authenticates

Leo's `google` OAuth provider carries Gmail, Drive and Calendar scopes — not
`cloud-platform` — and a person's own Google account usually isn't the identity that owns
the infrastructure anyway. So this package mints its own tokens: it signs a one-hour JWT
with the key's private half and exchanges it at `oauth2.googleapis.com` for an access
token, cached in memory until a minute before it expires. The key never leaves the hub.

What the service account's IAM roles allow is the real boundary. This package asks for one
scope (`cloud-platform`) and then can do exactly what you granted the account, no more.

## Icon

`assets/icon.svg` is the package's artwork — a white cloud on a Google-blue tile, drawn to
Leo's app-icon shape (512, `rx 114`).

A store entry with no UI bundle has no way to *deliver* artwork to a hub: icons travel
either compiled into a crate or alongside a bundle's `ui.js`, and an MCP-only package has
neither. So a fresh install shows the manifest glyph (`cloud`) until someone uploads this
file on that hub — Settings → Packages → Google Cloud → App Icon.

## Development

```bash
npm install
npm test        # 25 checks: credentials, the signed assertion, payload shaping, the tool surface
```

The test suite needs no Google project — it covers the parts that fail silently (payload
shaping, the JWT claim set, limit clamping) with real response shapes, trimmed.

## Publishing

```bash
./store/publish.sh            # upsert the store row, live
./store/publish.sh draft      # stage it for review at admin.leoconnect.io
```

`store/registry-entry.json` pins a 40-hex commit in its tarball URL and `publish.sh`
refuses a pin that isn't pushed — an unreachable SHA installs cleanly and then fails on
every hub at first launch, which is the one failure this repo can catch and nothing
downstream can.
