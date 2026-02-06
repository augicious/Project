# Operations / Production Notes

This app is a Flask site typically hosted with Waitress via `run_waitress.py`.

## Logging

Service logs are written to the `RiskTicketing` logs folder and are rotated to prevent unbounded growth.

**Environment variables**

- `LOG_LEVEL` (default: `INFO`)
  - Sets the service log level for `run_waitress.py`.
  - Examples: `DEBUG`, `INFO`, `WARNING`, `ERROR`.

- `RISK_TICKETING_LOG_MAX_MB` (default: `25`)
  - Max size in MB before the log rotates.

- `RISK_TICKETING_LOG_BACKUPS` (default: `5`)
  - Number of rotated log files to keep.

### Request correlation / access logs

The app supports request correlation IDs:

- If the client sends `X-Request-ID`, it will be used.
- Otherwise a new request id is generated.
- The server echoes the id back in the `X-Request-ID` response header.

Per-request access logging can be controlled with:

- `REQUEST_LOGGING_ENABLED` (default: `true`)
  - When `true`, each request logs a one-line access entry (method, path, status, duration, etc.).

- `LOG_HEALTH_REQUESTS` (default: `false`)
  - When `false`, requests to `/_health` are not included in access logs (keeps logs clean).

### Secret redaction

`run_waitress.py` applies a redaction filter so common secrets/tokens are masked if they appear in log messages.

This is a safety net, not a substitute for avoiding logging sensitive data.

## Health endpoint

- `GET /_health` returns JSON with `ok`, timestamp, uptime, and checks.
- Returns HTTP `200` when healthy.
- Returns HTTP `503` when unhealthy (DB not reachable, required directories not writable, etc.).

## Excel seeding

Excel seeding on startup is **opt-in**:

- `SEED_FROM_EXCEL_ON_STARTUP` (default: `false`)

When enabled, the app may import initial data from an Excel file during startup.
