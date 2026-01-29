# Risk Score Snapshots (Task Scheduler)

This app supports score snapshots for trends (see the Admin **Trends** page).

Snapshots are captured into the SQLite table `risk_score_snapshots`.

## Why Task Scheduler

- No hidden “auto” behavior in the web app
- No need to deal with admin auth/CSRF
- Reliable on Windows/IIS

## One-time manual run (sanity check)

From a PowerShell prompt:

- `C:\inetpub\wwwroot\Project\.venv\Scripts\python.exe "C:\inetpub\wwwroot\Project\Risk Assessment\scripts\capture_score_snapshot.py"`

If you installed Python via python.org, you may have the Windows launcher `py.exe` available:

- `py -3.12 "C:\inetpub\wwwroot\Project\Risk Assessment\scripts\capture_score_snapshot.py"`

You should see output like:

- `OK: captured snapshot_date=YYYY-MM-DD for N row(s) (M scored risk(s))`

## Register a monthly task

Use the helper script (run PowerShell as Administrator):

- `powershell -ExecutionPolicy Bypass -File "C:\inetpub\wwwroot\Project\Risk Assessment\scripts\register_score_snapshot_task.ps1" -DayOfMonth 1 -StartTime "02:00"`

If your production layout differs, pass:

- `-AppRoot "C:\inetpub\wwwroot\Project\Risk Assessment"`
- `-PythonExe "C:\inetpub\wwwroot\Project\.venv\Scripts\python.exe"`

If you’re using a system install of Python instead of a project venv, pass:

- `-PythonExe "C:\Program Files\Python312\python.exe"`

Notes:

- Scheduled tasks running as `SYSTEM` typically cannot access mapped drives like `V:\`.
- For production, use a local disk path (recommended) or a UNC path.
- A path like `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` is a Start Menu **shortcut folder**, not the location of `python.exe`.
- If the helper auto-detects `py.exe`, you can control the version with `-PythonLauncherVersion "3.12"`.

## Production recommendation

- Schedule monthly on day 1 at 02:00.
- Run as a service account or `SYSTEM` with access to the app folder and the SQLite DB.

## If you're running from an admin share (UNC)

If you browse the app as `\\hdh-websrv\c$\inetpub\wwwroot\Project\Risk Assessment`, use the equivalent local path when creating the scheduled task:

- Local: `C:\inetpub\wwwroot\Project\Risk Assessment`

Tasks running as `SYSTEM` should prefer local paths.
