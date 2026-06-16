<p align="center">
  <img src=https://github.com/origami-team/geogami/blob/master/src/assets/icons/icon.png width="100" alt="GeoGami logo"/>
</p>

<h1 align="center">GeoGami Server</h1>

<p align="center">
  REST API and real-time backend powering the <strong>GeoGami</strong> location-based game platform.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-20-339933?logo=node.js" alt="Node 20"/>
  <img src="https://img.shields.io/badge/Express-4.x-000000?logo=express" alt="Express 4"/>
  <img src="https://img.shields.io/badge/MongoDB-8.0-47A248?logo=mongodb" alt="MongoDB 8"/>
  <img src="https://img.shields.io/badge/Socket.IO-realtime-010101?logo=socketdotio" alt="Socket.IO"/>
</p>

This repository contains the GeoGami backend. It serves the REST endpoints used by the mobile/web client and the analytics dashboard, plus the **Socket.IO** layer that handles real-time multiplayer and avatar synchronisation with the Unity-based virtual environment.

> Companion projects:
> - **Front-end UI**: [`../geogami-ui`](https://github.com/geogami-team/geogami)
> - **Analytics dashboard**: [`../geogami-dashboard`](https://github.com/geogami-team/geogami-dashboard)
> - **Virtual environment**: [`../geogami-virtual-environment-dev`](https://github.com/geogami-team/geogami-virtual-environment-dev)

---

## Table of contents

- [Tech stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Quick start (Docker Compose)](#quick-start-docker-compose)
- [Local development without Docker](#local-development-without-docker)
- [Environment variables](#environment-variables)
- [Project structure](#project-structure)
- [API overview](#api-overview)
- [Authentication and authorisation](#authentication-and-authorisation)
- [Socket.IO events](#socketio-events)
- [Database migrations](#database-migrations)
- [Backups](#backups)
- [Logs](#logs)
- [Deployment](#deployment)

---

## Tech stack

| Area | Technology |
|---|---|
| Runtime | Node.js 20 |
| Web framework | Express 4 |
| Database | MongoDB 8 (via Mongoose) |
| Real-time | Socket.IO |
| Auth | Passport (JWT strategy) + bcrypt |
| Email | Nodemailer (SMTP) |
| Logging | Morgan + rotating file streams |
| Migrations | `migrate-mongo` |

## Prerequisites

- **Node.js 20** (or use the Docker image)
- **MongoDB** 6+ (local or remote)
- **SMTP credentials** for transactional email (verification, password reset)
- **Docker + Docker Compose** if you prefer the containerised path

## Quick start (Docker Compose)

The simplest way to spin up the API + a fresh Mongo instance:

```bash
cp .env.example .env        # then edit values (see table below)
docker compose up --build   # API on :3000, MongoDB on :27017
```

`docker-compose.yml` mounts:
- `./db` → Mongo's `/data/db` for persistent storage
- `./log` → application log files
- `./init-mongo-user.js` runs once on first start to provision the DB user

## Local development without Docker

```bash
yarn install
yarn dev      # runs nodemon, restarts on changes
# or
yarn start    # plain node
```

Make sure a MongoDB instance is reachable at the host/credentials in your `.env`.

## Environment variables

```env
# Runtime
NODE_ENV=development            # development = mock mailer prints to stdout

# MongoDB
MONGO_HOST=localhost:27017
MONGO_USERNAME=geogami
MONGO_PASSWORD=changeme

# SMTP / outbound email
MAIL_SMTP_HOST=smtp.example.com
MAIL_SMTP_PORT=587
MAIL_SMTP_USERNAME=postmaster@example.com
MAIL_SMTP_PASSWORD=changeme
MAIL_SENDER_ADDRESS=no-reply@geogami.example

# URLs used in confirmation links
API_URL=https://api.geogami.example
API_PORT=3000
APP_URL=https://app.geogami.example
APP_PORT=443
```

In **development** mode the mailer is replaced by a mock that logs the rendered email body to stdout — useful for testing flows without a real SMTP server.

## Project structure

```
src/
├── index.js              # Express + Socket.IO entry point
├── config/               # Mongo & passport config
├── controllers/          # authController, mailController, upload
├── middleware/           # JWT, role authorization, error handling
├── models/               # Mongoose schemas (User, Game, Track, Task, …)
├── routes/
│   ├── user/             # /user/* — register, login, profile, admin
│   ├── game/             # /game/* — CRUD + share + creator filters
│   ├── track/            # /track/* — gameplay sessions and waypoints
│   ├── file/             # File upload endpoints
│   └── appversion/       # App version checks for clients
└── helpers/              # Shared utilities
```

## API overview

The complete endpoint documentation — payloads, responses, role requirements, and gotchas — lives in the [REST API Reference](https://github.com/geogami-team/geogami-docs/blob/HEAD/API_REFERENCE.md) in `geogami-docs`. The tables below are a quick summary.

### Public endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/user/register` | Create an account, send verification email |
| POST | `/user/login` | Issue access + refresh tokens |
| POST | `/user/refresh-auth` | Rotate the access token |
| GET | `/user/confirm-email` | Confirm an email-verification link |
| POST | `/user/request-password-reset` | Email a password-reset code |
| POST | `/user/password-reset` | Set a new password |
| GET | `/game/all` | Public game list |

### Authenticated endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/user/myuser` | Current user profile |
| POST | `/user/resend-verification` | Self-serve resend (60s cooldown) |
| POST | `/user/change-mail` | Request an email change (sends link to new address) |
| GET | `/game/usergames` | Games the user owns, had shared with them, instructs, or has a shared track in |
| GET | `/game/:id/share` | List the emails a game is shared with |
| POST | `/game/:id/share` | Grant another user (by email) access to a game's tracks |
| DELETE | `/game/:id/share` | Revoke access |
| GET | `/track/gametracks/:id` | Tracks of a game the caller may see (creator / instructor / shared) |
| GET | `/track/:id` | A single track (owner, instructor, or share recipient) |
| GET | `/track/:id/share` | List the emails a track is shared with |
| POST | `/track/:id/share` | Share one track with another user (by email) |
| DELETE | `/track/:id/share` | Revoke a track share |

### Admin endpoints (`admin` / `contentAdmin`)

| Method | Path | Description |
|---|---|---|
| GET | `/user/user/` | List all users |
| POST | `/user/user/` | Create a user (hashed password, sends verification) |
| PUT | `/user/update-role` | Change a user's roles |
| DELETE | `/user/user/:id` | Delete a user |
| POST | `/user/user/:id/resend-verification` | Resend verification on behalf of a user |
| POST | `/user/user/:id/trigger-password-reset` | Send reset email to a user |
| GET | `/user/user/:id/games` | Games created by a user |

### Class sharing (instructor QR) & track access

Logged-in users can show a **Class QR code** for a single-player game (in the
UI's game-detail page). A student who opens that link/QR plays with data-sharing
consent locked on, and the resulting track is `POST`ed with the sharing user's id
as `instructor` (validated against a real user). Such *class tracks* surface in
the **instructor's** dashboard, not the game creator's.

Who may see a given track is enforced in `getGameTracks` / `getTrack` via the
shared rule in `helpers/trackAccess.js`:

| Caller | Sees |
|---|---|
| admin / contentAdmin | every track |
| game creator | only non-class tracks (no `instructor`) |
| game-share colleague (`game.sharedWith`) | only non-class tracks |
| instructor | only tracks where `instructor` == them |
| per-track share recipient (`track.sharedWith`) | only tracks shared with them |

`getUserGames` surfaces a game when the caller owns it, has it shared, instructs
on one of its tracks, or had one of its tracks shared with them — and reports a
track count scoped to that same rule. Indexes on `Track.instructor` and
`Track.sharedWith` keep these lookups off the historical backlog. `POST /track`
(unauthenticated, used by the player app) accepts an optional `instructor` in the
body and validates it; a per-track `sharedWith` can only be changed through the
authenticated `/track/:id/share` routes.

**QA matrix** (manual):

| Scenario | Expected |
|---|---|
| Creator plays own game | track has no `instructor` → creator sees it |
| Student plays via class QR | track has `instructor` → only the instructor sees it |
| Instructor shares one such track with a colleague | colleague sees just that track |
| Instructor revokes the share | colleague stops seeing it |
| Tracks created before this feature | still visible to creators as before |

## Authentication and authorisation

- **JWT access tokens** signed with the secret in `src/config/passport.js`.
- **Refresh tokens** stored on the User document (`refreshTokens[]`) so they can be revoked individually.
- **Roles**: `user`, `contentAdmin`, `trackAccess`, `admin`, `scholar`. Role checks are enforced via `AuthController.roleAuthorization([...])` middleware.
- **Email verification**: required to access the app, but unverified users still receive a token so they can reach `/user/verify-email` and trigger a resend. `unconfirmedEmail` is promoted to `email` once the link is opened, supporting safe email-change flows.

## Socket.IO events

Socket.IO is mounted on the same HTTP server (port 3000) and is used for:

- **Real-world multiplayer** — joining game rooms, syncing player connection status
- **Virtual environment sync** — relaying avatar position, rotation, and walking state between the GeoGami app and the Unity VR client
- **Game lifecycle** — start/stop, track-storage status, instructor view

Key events: `joinGame`, `newGame`, `joinVEGame`, `updateAvatarPosition`, `updateAvatarDirection`, `play`, `update_others_avatars_positions_periodically`.

## Database migrations

Migrations are managed with [`migrate-mongo`](https://github.com/seppevs/migrate-mongo). The configuration lives in `migrate-mongo-config.js`.

```bash
npx migrate-mongo status
npx migrate-mongo up
npx migrate-mongo create my-migration
```

## Backups

`backup.sh` (sample in `backup.example.sh`) dumps the Mongo database and rotates archives. Schedule it via cron on production hosts.

## Logs

Access logs are written via Morgan to `log/access.log` and rotated daily. Application errors go to stdout and are picked up by Docker logging.

## Deployment

The project ships a multi-stage `Dockerfile` (Node 20 Alpine). The provided `docker-compose.yml` is suitable for staging; for production we recommend:

- Putting the API behind a reverse proxy (nginx / Traefik) for TLS
- Using a managed MongoDB replica set
- Configuring a real SMTP relay (`NODE_ENV=production`)
- Mounting the `log/` and `db/` directories on persistent volumes

## License

MIT — see the parent project for citation information.
