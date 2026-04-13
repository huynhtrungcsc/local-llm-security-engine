# Deployment Guide — Local LLM Security Engine

This guide covers running the engine as a stable, persistent background service on both **Linux** and **Windows**. The basic development setup (Step 6 in `getting_started.md`) starts the server in your terminal and stops when you close it. This guide shows how to keep it running reliably.

> **Read `getting_started.md` first.** This guide assumes Ollama is already installed, the model is pulled, and Python dependencies are installed.

---

## Choose your setup

| Use case | Recommended approach |
|---|---|
| Development / quick testing | `uvicorn` in terminal (see `getting_started.md`) |
| Linux development machine | systemd user service |
| Linux server / headless | systemd system service |
| Windows development machine | PowerShell background job or NSSM |
| Windows server | NSSM Windows service |

---

## Linux

### Option A — systemd user service (recommended for development machines)

A systemd user service starts automatically when you log in and restarts if the process crashes.

**Step 1 — Create the service file**

Replace `/home/youruser/local-llm-security-engine` with the actual path to the cloned repo.

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/llm-security-engine.service << 'EOF'
[Unit]
Description=Local LLM Security Engine
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/youruser/local-llm-security-engine/llm-security-engine
ExecStart=/home/youruser/local-llm-security-engine/llm-security-engine/venv/bin/uvicorn \
    app.main:app \
    --host 0.0.0.0 \
    --port 8000
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF
```

> If you are **not** using a virtual environment, replace the `ExecStart` path with the output of `which uvicorn`.

**Step 2 — Enable and start the service**

```bash
systemctl --user daemon-reload
systemctl --user enable llm-security-engine
systemctl --user start llm-security-engine
```

**Step 3 — Verify it is running**

```bash
systemctl --user status llm-security-engine
```

You should see `Active: active (running)`.

```bash
curl http://localhost:8000/health
```

Should return `"status": "ok"`.

**Viewing logs:**

```bash
journalctl --user -u llm-security-engine -f
```

**Stopping / restarting:**

```bash
systemctl --user stop llm-security-engine
systemctl --user restart llm-security-engine
```

---

### Option B — systemd system service (server / headless Linux)

Use this when running on a dedicated server or when you want the service to start at boot regardless of who is logged in.

**Step 1 — Create a dedicated user (optional but recommended)**

```bash
sudo useradd --system --shell /bin/false --home /opt/llm-engine llm-engine
sudo mkdir -p /opt/llm-engine
sudo chown llm-engine:llm-engine /opt/llm-engine
```

Clone the repo to `/opt/llm-engine`:

```bash
sudo -u llm-engine git clone https://github.com/huynhtrungcsc/local-llm-security-engine.git /opt/llm-engine/app
```

Set up the virtual environment:

```bash
sudo -u llm-engine python3 -m venv /opt/llm-engine/venv
sudo -u llm-engine /opt/llm-engine/venv/bin/pip install -r /opt/llm-engine/app/llm-security-engine/requirements.txt
```

Copy and edit the configuration:

```bash
sudo -u llm-engine cp \
  /opt/llm-engine/app/llm-security-engine/.env.example \
  /opt/llm-engine/app/llm-security-engine/.env
sudo nano /opt/llm-engine/app/llm-security-engine/.env
```

**Step 2 — Create the system service file**

```bash
sudo tee /etc/systemd/system/llm-security-engine.service << 'EOF'
[Unit]
Description=Local LLM Security Engine
After=network.target

[Service]
Type=simple
User=llm-engine
Group=llm-engine
WorkingDirectory=/opt/llm-engine/app/llm-security-engine
ExecStart=/opt/llm-engine/venv/bin/uvicorn \
    app.main:app \
    --host 0.0.0.0 \
    --port 8000
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/llm-engine/app/llm-security-engine

[Install]
WantedBy=multi-user.target
EOF
```

**Step 3 — Enable and start**

```bash
sudo systemctl daemon-reload
sudo systemctl enable llm-security-engine
sudo systemctl start llm-security-engine
sudo systemctl status llm-security-engine
```

**Viewing logs:**

```bash
sudo journalctl -u llm-security-engine -f
```

---

### Ollama as a systemd service (Linux)

On most Linux installations, Ollama already registers a systemd service during install. Verify:

```bash
systemctl status ollama
```

If it is running, you do not need to do anything. If it is not:

```bash
sudo systemctl enable ollama
sudo systemctl start ollama
```

If Ollama is not registered as a service (manual install), create one:

```bash
sudo tee /etc/systemd/system/ollama.service << 'EOF'
[Unit]
Description=Ollama Local LLM Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ollama serve
Restart=on-failure
RestartSec=3
Environment=OLLAMA_HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl start ollama
```

---

### Linux firewall (ufw)

If you need the engine to be reachable from another machine on the same network (or through a tunnel), open port 8000:

```bash
sudo ufw allow 8000/tcp comment "LLM Security Engine"
sudo ufw reload
sudo ufw status
```

> **Security note**: Do not expose port 8000 to the public internet without enabling authentication (`LOCAL_LLM_API_KEY` in `.env`). Use a reverse proxy (nginx, Caddy) with TLS for production external access.

---

### Linux quick reference

```bash
# Start / stop / restart
systemctl --user start  llm-security-engine
systemctl --user stop   llm-security-engine
systemctl --user restart llm-security-engine

# View logs (live)
journalctl --user -u llm-security-engine -f

# Check Ollama
systemctl status ollama
curl http://localhost:11434/api/tags

# Check engine
curl http://localhost:8000/health

# Reload config after editing .env
systemctl --user restart llm-security-engine
```

---

## Windows

### Prerequisites check

Open **PowerShell** (not Command Prompt — PowerShell has better support for modern Python workflows):

```powershell
python --version
# Expected: Python 3.10.x or higher
# If missing: download from https://www.python.org/downloads/
# During install: check "Add Python to PATH"

pip --version
# Should print pip version

# Verify Ollama is installed
ollama --version
# If missing: download from https://ollama.ai (the .exe installer)
```

---

### Set up the project

Clone the repo or download and extract the ZIP from GitHub:

```powershell
git clone https://github.com/huynhtrungcsc/local-llm-security-engine.git
cd local-llm-security-engine\llm-security-engine
```

Create a virtual environment and install dependencies:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Copy the configuration file:

```powershell
copy .env.example .env
notepad .env
```

The defaults work for local development. No changes required for a basic setup.

---

### Option A — Run in PowerShell terminal (development)

This is the simplest option. Start a terminal and run:

```powershell
cd path\to\local-llm-security-engine\llm-security-engine
venv\Scripts\activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The server runs until you close the terminal or press `Ctrl+C`.

**Verify it is running** (open a second PowerShell window):

```powershell
Invoke-RestMethod -Uri http://localhost:8000/health | ConvertTo-Json
```

Or with curl (available in PowerShell 7+ and Windows Terminal):

```powershell
curl http://localhost:8000/health
```

---

### Option B — Run as a background PowerShell job (development)

Start the server in the background without keeping a terminal window open:

```powershell
$job = Start-Job -ScriptBlock {
    Set-Location "C:\path\to\local-llm-security-engine\llm-security-engine"
    & "venv\Scripts\uvicorn.exe" app.main:app --host 0.0.0.0 --port 8000
}
Write-Host "Engine started as job $($job.Id)"
```

Check the job is running:

```powershell
Get-Job
Receive-Job -Id $job.Id   # view output
```

Stop it:

```powershell
Stop-Job -Id $job.Id
Remove-Job -Id $job.Id
```

---

### Option C — Windows service with NSSM (recommended for production)

NSSM (Non-Sucking Service Manager) wraps any executable as a proper Windows service that starts at boot, restarts on crash, and writes logs automatically.

**Step 1 — Install NSSM**

Download from [nssm.cc](https://nssm.cc/download) and extract. Copy `nssm.exe` to `C:\Windows\System32\` so it is on the PATH.

Or install with Scoop:

```powershell
scoop install nssm
```

**Step 2 — Register the service**

Open PowerShell **as Administrator**:

```powershell
nssm install LlmSecurityEngine
```

This opens a GUI. Fill in:

| Field | Value |
|---|---|
| Path | `C:\path\to\local-llm-security-engine\llm-security-engine\venv\Scripts\uvicorn.exe` |
| Startup directory | `C:\path\to\local-llm-security-engine\llm-security-engine` |
| Arguments | `app.main:app --host 0.0.0.0 --port 8000` |

In the **Details** tab:
- Display name: `LLM Security Engine`
- Description: `Local LLM inference service for security event analysis`
- Startup type: `Automatic`

In the **Log on** tab, keep `Local System account` for a single-user machine, or use a dedicated service account.

Click **Install service**.

**Step 3 — Set the working directory (if GUI did not take it)**

```powershell
nssm set LlmSecurityEngine AppDirectory "C:\path\to\local-llm-security-engine\llm-security-engine"
```

**Step 4 — Configure log files (optional)**

```powershell
nssm set LlmSecurityEngine AppStdout "C:\Logs\llm-engine-stdout.log"
nssm set LlmSecurityEngine AppStderr "C:\Logs\llm-engine-stderr.log"
nssm set LlmSecurityEngine AppRotateFiles 1
nssm set LlmSecurityEngine AppRotateSeconds 86400
```

**Step 5 — Start the service**

```powershell
nssm start LlmSecurityEngine

# Verify
nssm status LlmSecurityEngine
# Expected: SERVICE_RUNNING
```

**Verify the engine is up:**

```powershell
Start-Sleep -Seconds 3
Invoke-RestMethod -Uri http://localhost:8000/health | ConvertTo-Json
```

**NSSM quick reference:**

```powershell
nssm start   LlmSecurityEngine
nssm stop    LlmSecurityEngine
nssm restart LlmSecurityEngine
nssm status  LlmSecurityEngine
nssm remove  LlmSecurityEngine confirm   # uninstall the service
```

---

### Ollama on Windows

Ollama installs as a Windows background service automatically when you run the `.exe` installer. After installation it appears in the system tray and starts at login.

**Verify Ollama is running:**

```powershell
Invoke-RestMethod -Uri http://localhost:11434/api/tags | ConvertTo-Json
```

If Ollama is not running, right-click the Ollama icon in the system tray → **Start**. Or launch "Ollama" from the Start menu.

**Pull the model** (one-time):

```powershell
ollama pull phi4-mini
ollama list     # verify phi4-mini appears
```

---

### Windows Firewall

If you need port 8000 reachable from another machine on the same network:

```powershell
# Run as Administrator
New-NetFirewallRule `
  -DisplayName "LLM Security Engine" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8000 `
  -Action Allow

# Verify
Get-NetFirewallRule -DisplayName "LLM Security Engine" | Select-Object Name, Enabled, Direction
```

To remove the rule later:

```powershell
Remove-NetFirewallRule -DisplayName "LLM Security Engine"
```

---

### Windows quick reference

```powershell
# Check Ollama
ollama list
Invoke-RestMethod http://localhost:11434/api/tags

# Check engine
Invoke-RestMethod http://localhost:8000/health | ConvertTo-Json

# Service management (if using NSSM)
nssm start   LlmSecurityEngine
nssm stop    LlmSecurityEngine
nssm restart LlmSecurityEngine

# Reload config after editing .env (NSSM service)
nssm restart LlmSecurityEngine

# View service logs (if log files configured)
Get-Content "C:\Logs\llm-engine-stdout.log" -Tail 50 -Wait
```

---

## Sending a test request from PowerShell

On Windows, `curl` is an alias for `Invoke-WebRequest` by default, which behaves differently from the curl shown in other docs. Use `Invoke-RestMethod` instead:

```powershell
$body = @{
    description = "57 failed SSH login attempts followed by one successful login from 185.220.101.1."
    source_ip   = "185.220.101.1"
    event_type  = "authentication_failure"
    severity    = "high"
} | ConvertTo-Json

$response = Invoke-RestMethod `
    -Method Post `
    -Uri http://localhost:8000/analyze-event `
    -ContentType "application/json" `
    -Body $body

$response | ConvertTo-Json
```

Or, if you prefer the exact curl syntax, install curl for Windows from [curl.se](https://curl.se/windows/) and use it explicitly (not the PowerShell alias):

```powershell
& "C:\Program Files\curl\bin\curl.exe" -X POST http://localhost:8000/analyze-event `
  -H "Content-Type: application/json" `
  -d '{
    "description": "57 failed SSH login attempts followed by one successful login from 185.220.101.1.",
    "source_ip": "185.220.101.1",
    "event_type": "authentication_failure",
    "severity": "high"
  }'
```

---

## Running the unit tests

Tests run without a live server or Ollama instance (all mocked):

**Linux / macOS:**
```bash
cd llm-security-engine
source venv/bin/activate     # if using venv
python -m pytest tests/ -v
```

**Windows (PowerShell):**
```powershell
cd llm-security-engine
venv\Scripts\activate
python -m pytest tests/ -v
```

Expected: **126 passed**.

---

## Environment variable reference

All configuration is done through the `.env` file in `llm-security-engine/`.

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `phi4-mini` | Model name (must be pulled with `ollama pull`) |
| `OLLAMA_TIMEOUT` | `60` | Seconds to wait for Ollama response. Increase to `120` for slow machines. |
| `API_HOST` | `0.0.0.0` | Interface to listen on (`0.0.0.0` = all interfaces) |
| `API_PORT` | `8000` | Port for the HTTP server |
| `LOCAL_LLM_API_KEY` | *(unset)* | If set, all analysis endpoints require `X-API-Key: <value>` |
| `RATE_LIMIT_ENABLED` | `true` | Enable/disable rate limiting |
| `RATE_LIMIT_REQUESTS` | `60` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window in seconds |
| `MAX_DESCRIPTION_LENGTH` | `4000` | Max characters for the description field |
| `MAX_CONTEXT_LENGTH` | `4000` | Max characters for context summary |
| `DEBUG` | `false` | Enable debug logging |

After editing `.env`, restart the service (systemd or NSSM) for changes to take effect.

---

## What to read next

- [docs/getting_started.md](getting_started.md) — step-by-step first-time setup
- [docs/end_to_end_integration.md](end_to_end_integration.md) — connecting the SOC backend to the engine
- [docs/troubleshooting.md](troubleshooting.md) — diagnosing common problems
