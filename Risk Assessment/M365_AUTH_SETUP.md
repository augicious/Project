# Microsoft 365 (Entra ID) Authentication Setup

This app supports Microsoft 365 sign-in (Microsoft Entra ID / Azure AD) using OpenID Connect.

## 1) Create an App Registration

1. Go to Azure Portal → Microsoft Entra ID → **App registrations** → **New registration**.
2. Name: e.g. **HDH RISKS**
3. Supported account types:
   - Usually **Single tenant** (recommended for internal apps).
4. Redirect URI (Web):
   - `https://reportrisks.hdh.org/auth/callback`

After creation, copy:
- **Application (client) ID** → `OIDC_CLIENT_ID`
- **Directory (tenant) ID** → `OIDC_TENANT_ID`

### Create a Client Secret
Azure Portal → App registration → **Certificates & secrets** → **New client secret**
- Copy the secret value immediately
- Set it as `OIDC_CLIENT_SECRET`

## 2) Optional Token Configuration (Recommended)

Azure Portal → App registration → **Token configuration**
- Add optional claim: **email** (ID token)
- Add optional claim: **upn** (ID token)

The app will use `preferred_username` / `upn` / `email` to display the signed-in user.

## 3) Configure Environment Variables on the Server

Set these environment variables for the service user (the account running NSSM/Waitress):

- `FLASK_SECRET_KEY` (required; strong random value)
- `OIDC_TENANT_ID`
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`
- `OIDC_REDIRECT_URI` = `https://reportrisks.hdh.org/auth/callback`
- `OIDC_POST_LOGOUT_REDIRECT_URI` = `https://reportrisks.hdh.org/`

Optional:
- `AUTH_REQUIRED` = `true` (default) to require login for the whole site
  - Set `AUTH_REQUIRED=false` temporarily to disable enforcement (useful during setup)

Restart the Windows service after changing env vars.

### Notes: NSSM vs an env file

You generally do **not** need a separate “environment file” for production. The safest/cleanest options are:

1) **Machine-level environment variables** (recommended)
  - Set via PowerShell (`[Environment]::SetEnvironmentVariable(..., "Machine")`) or System Properties → Environment Variables.
  - Works regardless of whether you run the app via NSSM, `sc.exe`, or Task Scheduler.

2) **NSSM service-specific environment**
  - You can keep secrets out of global machine env vars by setting them only for the service:
    - `nssm set <ServiceName> AppEnvironmentExtra "OIDC_TENANT_ID=..."`
    - `nssm set <ServiceName> AppEnvironmentExtra "OIDC_CLIENT_ID=..."`
    - `nssm set <ServiceName> AppEnvironmentExtra "OIDC_CLIENT_SECRET=..."`
    - `nssm set <ServiceName> AppEnvironmentExtra "OIDC_REDIRECT_URI=..."`
  - If your NSSM is at `C:\Temp\nssm\pkg\tools\nssm-2.24-101-g897c7ad\nssm-2.24-101-g897c7ad\win64`, you can run it via the full path (no need to add to PATH), e.g.:
    - `C:\Temp\nssm\pkg\tools\...\win64\nssm.exe set <ServiceName> AppEnvironmentExtra "OIDC_TENANT_ID=..."`

3) **Env file (.env)** (good for local dev; optional for servers)
  - The app supports loading a `.env` if `python-dotenv` is installed.
  - For servers, if you do this, store it outside the repo and lock down permissions, e.g. `C:\ProgramData\RiskTicketing\.env`.
  - Point the app at it by setting `ENV_FILE=C:\ProgramData\RiskTicketing\.env`.
  - Do not commit `.env` to git.

## 4) IIS Reverse Proxy Notes (ARR + URL Rewrite)

Because IIS terminates TLS and proxies to Waitress over HTTP, the Flask app needs forwarded headers.

The included `web.config` sets:
- `X-Forwarded-Proto: https`
- `X-Forwarded-Host: {HTTP_HOST}`
- `X-Forwarded-For: {REMOTE_ADDR}`

Important IIS setting:
- IIS may block setting these server variables until you allow them.
- In IIS Manager → **URL Rewrite** → **View Server Variables…** → **Add**:
  - `HTTP_X_FORWARDED_PROTO`
  - `HTTP_X_FORWARDED_HOST`
  - `HTTP_X_FORWARDED_FOR`

Also ensure ARR is configured to **preserve host header** (common for correct redirect behavior).

## 5) Admin Access

Microsoft 365 sign-in controls access to the site.

Admin functionality still uses the existing admin password prompt (the `/admin` page) after sign-in.
If you’d like admin to be based on Microsoft 365 group membership instead, tell me the group name/ID and I’ll wire it up.
