# Email Notifications Setup (Risk Ticketing)

This app can send notification emails via SMTP for:
- New **Critical** risk submissions
- Risk assignment changes (admin edit + bulk update)

## Environment variables

Set these in your service environment or `.env` (recommended via `ENV_FILE`).

### SMTP (required to send anything)

- `SMTP_HOST` (required)
- `SMTP_PORT` (optional, default `587`)
- `SMTP_USE_TLS` (optional, default `true`)
- `SMTP_USER` (optional; often required by your mail server)
- `SMTP_PASSWORD` (optional; often required by your mail server)

### Message identity

- `SMTP_FROM` (optional, default `noreply@hdh.org`)
- `SMTP_REPLY_TO` (optional, default `VFSA@hdh.org`)

Note: some SMTP servers require `SMTP_FROM` to match (or be allowed for) the authenticated `SMTP_USER`.

### Recipients / toggles

- `NOTIFY_CRITICAL_TO` (comma-separated list; required to send Critical alerts)
  - Example: `NOTIFY_CRITICAL_TO=VFSA@hdh.org,riskmanagement@hdh.org`
- `NOTIFY_ASSIGNMENT_ENABLED` (optional, default `true`)

### Base URL (recommended)

Links in emails use:
- `APP_BASE_URL` if set (recommended for IIS deployments)
- otherwise it falls back to the current request host

Example:
- `APP_BASE_URL=https://reportrisk.hdh.org`

## Example `.env`

```env
SMTP_HOST=smtp.hdh.org
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=VFSA@hdh.org
SMTP_PASSWORD=REDACTED
SMTP_FROM=noreply@hdh.org
SMTP_REPLY_TO=VFSA@hdh.org

NOTIFY_CRITICAL_TO=VFSA@hdh.org,riskmanagement@hdh.org
NOTIFY_ASSIGNMENT_ENABLED=true

APP_BASE_URL=https://reportrisk.hdh.org
```

## Troubleshooting

- If emails don’t send, verify:
  - outbound SMTP is allowed from the server
  - host/port/TLS match your mail server
  - authentication requirements (user/password)
  - sender restrictions (some servers reject mismatched `From`)

## Attachment archiving (closed risks)

To reduce hot storage usage, the app can **archive attachments** for risks that are:
- `Closed`
- have a `closed_at` date older than a cutoff (default 180 days)

Archiving moves files from the active upload folder into an archive folder, and the UI will label them as **Archived**. Risks/tickets are not deleted.

### Environment variables

- `ATTACHMENT_ARCHIVE_AFTER_DAYS` (optional, default `180`)
- `ATTACHMENT_ARCHIVE_DIR` (optional, default `data/uploads_archive`)

### Running the archive

From the Admin Dashboard header, use **Archive old attachments** (this triggers a POST to `/admin/attachments/archive_closed`).
