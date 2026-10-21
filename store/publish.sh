#!/usr/bin/env bash
#
# Publish (or update) this package in the Leo store.
#
# The store is a Cloudflare D1 behind admin.leoconnect.io: the rows marked
# `active` there *are* what registry.leoconnect.io/registry.json serves, so an
# insert here is the whole publishing mechanism. There is no repo in the loop
# and no build step.
#
#   ./store/publish.sh            # publish live
#   ./store/publish.sh draft      # stage it for review at admin.leoconnect.io
#   ./store/publish.sh --local    # against a local `wrangler dev` D1
#
# Needs a Cloudflare login with D1:Edit on the leo-store database
# (`npx wrangler login`, or CLOUDFLARE_API_TOKEN in the environment).
set -euo pipefail

cd "$(dirname "$0")/.."
ENTRY=store/registry-entry.json
DB=leo-store
REMOTE=--remote
STATUS=active

for arg in "$@"; do
  case "$arg" in
    --local) REMOTE=--local ;;
    draft|active|inactive|rejected) STATUS="$arg" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# The pin must name a real commit that is actually pushed. A SHA that resolves
# nowhere installs cleanly and then fails on every hub at first launch, which is
# the one failure this file can prevent and nothing downstream can.
#
# Both pinned shapes are read: the `#<sha>` of a git spec, and the `<sha>` in an
# archive URL path. This package ships as the second — npm does not reliably run
# build steps for a tarball, which is why there is no npm publish behind it.
SHA=$(python3 - "$ENTRY" <<'PY'
import json, re, sys
entry = json.load(open(sys.argv[1]))
args = " ".join(entry["mcp"]["args"])
m = re.search(r"[#/]([0-9a-f]{40})\b", args)
if not m:
    sys.exit("registry-entry.json: mcp.args has no 40-hex commit pin")
print(m.group(1))
PY
)

if ! git cat-file -e "$SHA^{commit}" 2>/dev/null; then
  echo "pinned commit $SHA is not in this clone" >&2; exit 1
fi
if ! git branch -r --contains "$SHA" 2>/dev/null | grep -q origin/; then
  echo "pinned commit $SHA is not pushed — hubs could not fetch it" >&2; exit 1
fi

NAME=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$ENTRY")
echo "publishing '$NAME' at $SHA as status=$STATUS"

# Built with python so the JSON is escaped for SQL rather than interpolated and
# hoped over. Upsert, so re-running to bump the pin is the same command.
SQL=$(mktemp); trap 'rm -f "$SQL"' EXIT
python3 - "$ENTRY" "$STATUS" > "$SQL" <<'PY'
import json, sys
from datetime import datetime, timezone

entry = json.load(open(sys.argv[1]))
status = sys.argv[2]
blob = json.dumps(entry, separators=(",", ":"))
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
q = lambda s: "'" + s.replace("'", "''") + "'"

print(
    "INSERT INTO packages (name, entry_json, status, created_at, updated_at) VALUES "
    f"({q(entry['name'])}, {q(blob)}, {q(status)}, {q(now)}, {q(now)}) "
    "ON CONFLICT(name) DO UPDATE SET "
    "entry_json = excluded.entry_json, status = excluded.status, updated_at = excluded.updated_at;"
)
PY

npx wrangler d1 execute "$DB" $REMOTE --file "$SQL"

echo
echo "done. the catalog is CDN-cached for ~60s; then:"
echo "  curl -s https://registry.leoconnect.io/registry.json | jq '.packages[] | select(.name==\"$NAME\")'"
