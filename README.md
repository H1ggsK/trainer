# Clicker Trainer

A small server + browser client for remote clicker-training experiments.

The server runs a password-protected trainer panel, stores event logs in SQLite, and talks to pet clients over WebSockets. The pet client runs in the pet's browser and performs local pose/person detection. Camera images are only sent if the pet explicitly allows live feed access and a trainer turns the view on.

## Versioning

Server and browser client both advertise `PROTOCOL_VERSION = "1.0.0"`. They must share the same major protocol version or the connection is rejected.

## Server

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r server/requirements.txt
TRAINER_PASSWORD='change-this' uvicorn server.app.main:app --host 0.0.0.0 --port 8000
```

Then open `http://YOUR_VPS_IP:8000`.

For the pet link on a real VPS, put the server behind HTTPS. Browsers usually block camera access on plain `http://` unless it is `localhost`.

Default login:

- username: `trainer`
- Docker/Compose password: printed in the container logs at startup
- local non-Docker password: value of `TRAINER_PASSWORD`, or `trainer` if unset

The first account is an admin account. Admins manage trainer accounts at `/admin` and cannot access pet controls or pet logs. Create a separate trainer account from `/admin`, log out, then log in with that trainer account to use the training panel at `/`.

For Docker:

```bash
docker build -f server/Dockerfile -t clicker-trainer-server .
docker run --rm -p 8000:8000 \
  -e TRAINER_PASSWORD_RANDOM_EACH_START=1 \
  -e SESSION_SECRET='long-random-secret' \
  -v clicker_data:/data \
  -v ./server/audio:/data/audio:ro \
  clicker-trainer-server
```

For Docker Compose:

```bash
docker compose up --build
```

With the included compose file, open `http://localhost:9000`. Compose reads local secrets from `.env`, which is gitignored. After first boot you can add/remove pet codes and trainer accounts from the trainer panel.

When `TRAINER_PASSWORD_RANDOM_EACH_START=1`, Docker prints a fresh admin password every container start and resets the admin account to that password. See it with:

```bash
docker compose logs trainer
```

## Pet Client

Put audio files here:

- local dev: `server/audio/beep.mp3` and `server/audio/click.mp3`
- Docker: mount/copy them into `/data/audio/beep.mp3` and `/data/audio/click.mp3`

The repo's old prototype audio files can be copied there if you want:

```bash
cp old/beep.mp3 server/audio/beep.mp3
cp old/click.mp3 server/audio/click.mp3
```

Fresh databases start with no pets. A trainer must add each pet and code from the training panel. The trainer panel shows the pet login link; the pet opens that link, enters their code, grants camera permission, and leaves the page open. No install is required.

## Features In V1

- Trainer login-protected web panel
- Client/server protocol version handshake
- Server-side stay-in-frame toggle
- Optional stay-in-frame timer that silently disables the rule
- Browser-side pose/person detection with MediaPipe Tasks Vision
- Presence event log: left frame, returned, connected, disconnected
- Server-side random click scheduler with min/max interval
- Manual trainer click button
- Multiple pets with manually managed login codes
- Multiple trainers, with admin-managed trainer accounts
- Optional client-approved live feed view
- SQLite persistence for logs and settings
