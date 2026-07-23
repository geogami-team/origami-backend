# How to upgrade MongoDB

Runbook for moving the GeoGami database to a newer MongoDB version — typically to
pick up a security patch flagged by a CVE advisory. It assumes the Docker Compose
setup in this repository (`mongo` service, database `origami`, data stored in the
`./db` bind mount).

> **TL;DR** Back up → bump the image tag → `pull` + recreate → verify → (later)
> raise the Feature Compatibility Version. Never skip the backup, and never jump
> more than one minor version in a single step.

---

## When to upgrade

- A CVE advisory lists your running version as affected. Check the fix version on
  the [MongoDB Security Bulletins](https://www.mongodb.com/resources/products/mongodb-security-bulletins)
  page and confirm the exact CVE with IT.
- You are on a line that is nearing end-of-support (see
  [MongoDB lifecycle schedules](https://www.mongodb.com/legal/support-policy/lifecycles)).

The `mongo` service is intentionally **excluded from Watchtower auto-updates**
(`com.centurylinklabs.watchtower.enable=false` in `docker-compose.yml`), so the
database is **never** upgraded automatically — every version change is a deliberate,
reviewed operation using the steps below. Leave that label as-is.

## Understand the release model first

MongoDB's version string is `MAJOR.MINOR.PATCH` (e.g. `8.3.7`).

| Change | Example | Rule |
|---|---|---|
| **Patch** | `8.3.6 → 8.3.7` | Drop-in. Same feature set, just fixes. Safe. |
| **Minor** | `8.2.x → 8.3.x` | Supported **one step at a time**; involves an FCV bump. |
| **Major** | `7.0.x → 8.0.x` | Also one step at a time; plan carefully. |

Three rules that matter:

1. **No skipping.** To go from `8.0` to `8.3` you must step through `8.1` and `8.2`
   in order — you cannot jump straight across minor versions.
2. **Downgrades are restricted.** Only `8.3+` supports a single-version downgrade.
   Moving *back* below that (e.g. `8.2 → 8.0`) is **not** an in-place operation — it
   requires a `mongodump` / `mongorestore` migration.
3. **Patch bumps within a line are always safe** and need no FCV change.

## Before you start — checklist

- [ ] Confirm the target version is at most **one minor** above the current one.
- [ ] Know the current version: `docker compose exec mongo mongosh --quiet --eval 'db.version()'`
- [ ] Take a fresh backup (next section).
- [ ] Have a maintenance window — the `mongo` container restarts during the upgrade.
- [ ] Read the target version's [release notes](https://www.mongodb.com/docs/manual/release-notes/)
      for any breaking changes.

---

## Step-by-step (Docker Compose)

Run these from the server repo directory (production:
`/home/ubuntu/geogami-backend`). On the production host Compose is invoked as
`docker-compose` (v1); locally it is `docker compose` (v2) — adjust accordingly.

### 1. Back up

This is the rollback safety net. It mirrors `backup.sh`:

```bash
docker compose exec -T mongo mongodump \
  --username "$MONGO_USERNAME" --password "$MONGO_PASSWORD" \
  --authenticationDatabase admin \
  --archive --gzip --db origami \
  > geogami_backup_pre-upgrade_$(date +%F).gz
```

Keep the archive somewhere off the host until the upgrade is confirmed good.

### 2. Bump the image tag

Edit **both** compose files so they stay in sync:

- `docker-compose.yml` → `image: mongo:<new-version>`
- `docker-compose-example.yml` → `image: mongo:<new-version>`

Always pin an exact patch version (e.g. `mongo:8.3.7`), never a floating tag like
`mongo:8.3`, so deployments are deterministic and auditable.

### 3. Pull and recreate the container

```bash
docker compose pull mongo
docker compose up -d mongo
docker compose logs -f mongo    # watch it start; Ctrl-C when healthy
```

The `./db` bind mount holds the data files (and the FCV setting), so nothing is
lost across the container recreation.

### 4. Verify

```bash
# binary version is the new one
docker compose exec mongo mongosh --quiet \
  -u "$MONGO_USERNAME" -p "$MONGO_PASSWORD" --authenticationDatabase admin \
  --eval 'db.version()'

# current feature compatibility version (still the OLD minor at this point)
docker compose exec mongo mongosh --quiet \
  -u "$MONGO_USERNAME" -p "$MONGO_PASSWORD" --authenticationDatabase admin \
  --eval 'db.adminCommand({ getParameter: 1, featureCompatibilityVersion: 1 })'
```

Then confirm the app reconnected cleanly:

```bash
docker compose logs --tail=50 app
```

Exercise a couple of real flows (login, load a game, save a track) before moving on.

### 5. Raise the Feature Compatibility Version (finalize)

The **security fix is already live after step 3** — it ships in the binary and does
**not** depend on FCV. Leaving FCV at the previous minor is what keeps a rollback
possible, so **do this step only once you are confident you will not roll back**
(hours to a few days later is fine):

```bash
docker compose exec mongo mongosh \
  -u "$MONGO_USERNAME" -p "$MONGO_PASSWORD" --authenticationDatabase admin \
  --eval 'db.adminCommand({ setFeatureCompatibilityVersion: "<new-minor>", confirm: true })'
```

Use the `MAJOR.MINOR` only, e.g. `"8.3"`. The `confirm: true` field is required on
MongoDB 7.0+. Do not leave FCV pinned to an old value indefinitely — a future
upgrade will refuse to proceed until FCV matches the current version.

---

## Rolling back

- **If you have NOT yet raised FCV (step 5):** set the image tag back to the
  previous version in both compose files, then `docker compose pull mongo &&
  docker compose up -d mongo`. The old binary reads the data files unchanged.
- **If you HAVE raised FCV:** an in-place downgrade is only possible to the
  immediately previous minor (8.3+), and only if no backwards-incompatible
  features were persisted. Otherwise, restore from the step-1 backup:

  ```bash
  docker compose exec -T mongo mongorestore \
    --username "$MONGO_USERNAME" --password "$MONGO_PASSWORD" \
    --authenticationDatabase admin \
    --archive --gzip --drop < geogami_backup_pre-upgrade_<date>.gz
  ```

## Crossing multiple versions

To move several minors at once (e.g. `8.0 → 8.3`), repeat the whole cycle for each
step — `8.0 → 8.1`, then `8.1 → 8.2`, then `8.2 → 8.3` — raising FCV between steps
as needed. Do not edit the tag straight to the far target; the server will refuse
to start on data that is too many versions behind.

## References

- [Upgrade a self-managed standalone (MongoDB Docs)](https://www.mongodb.com/docs/manual/release-notes/8.3-upgrade-standalone/)
- [`setFeatureCompatibilityVersion`](https://www.mongodb.com/docs/manual/reference/command/setFeatureCompatibilityVersion/)
- [MongoDB versioning (major vs minor)](https://www.mongodb.com/docs/manual/reference/versioning/)
- [MongoDB Security Bulletins](https://www.mongodb.com/resources/products/mongodb-security-bulletins)
- [Software lifecycle schedules](https://www.mongodb.com/legal/support-policy/lifecycles)
