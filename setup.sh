#!/bin/bash
set -e
set -o pipefail

DEFAULT_WORK_DIR="/tmp/dstatubuntu"
REPO_URL="https://github.com/umbx-dot/udstat.git" # Or umbx-dot/secs if that's the correct repo
VENV_NAME="venv"
APP_MAIN_SCRIPT="app.py"
WEB_APP_PORT_EXPECTED=8000
MONITORED_UDP_PORT_EXPECTED=53 # From app.py
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/1376100805110923356/Krqs1KuXjvzw5jLGJ6l8PZ-mx-3N_V9jcKnOgf03_J8ASYKbbhE8B4j_wWwr5k3nwGCv"

log_message() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"
}

error_message() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2
}

send_discord_notification() {
    local public_ip="$1"
    local port="$2"
    local message_content="✅ Ubuntu dstat started successfully on: ${public_ip}:${port}"
    local payload
    payload=$(printf '{"content": "%s"}' "$message_content")

    log_message "Sending Discord notification..."
    curl -s -S -H "Content-Type: application/json" -X POST -d "$payload" "${DISCORD_WEBHOOK_URL}" || {
        error_message "Failed to send Discord notification. Curl exit code: $?"
    }
    echo # Newline after curl output
}

if [ "$(id -u)" -ne 0 ]; then
    error_message "This script must be run as root. Please use 'sudo bash ${0}' or 'curl ... | sudo bash'."
    exit 1
fi

WORK_DIR="${1:-${DEFAULT_WORK_DIR}}"
APP_DIR_NAME=$(basename "${REPO_URL}" .git)
APP_PATH="${WORK_DIR}/${APP_DIR_NAME}"
APP_NOHUP_LOG="${WORK_DIR}/idom_app_nohup.log"

log_message "Starting iDOM UDP Monitor Advanced Setup..."
log_message "Working directory: ${WORK_DIR}"
log_message "App path: ${APP_PATH}"
log_message "App log: ${APP_NOHUP_LOG}"

mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

if [ -d "${APP_DIR_NAME}" ]; then
    log_message "Cleaning up existing application directory: ${APP_DIR_NAME}"
    if [ -f "${APP_PATH}/${VENV_NAME}/bin/python3" ]; then
        pkill -f "${APP_PATH}/${VENV_NAME}/bin/python3 .*/${APP_MAIN_SCRIPT}" || true # More specific pkill
        sleep 2
    fi
    rm -rf "${APP_DIR_NAME}"
fi

log_message "Installing/Updating system dependencies (git, python3, python3-pip, python3-venv, curl, dos2unix)..."
apt-get update -y > /dev/null
apt-get install -y git python3 python3-pip python3-venv curl dos2unix > /dev/null

log_message "Cloning repository: ${REPO_URL}"
git clone --quiet "${REPO_URL}"
if [ ! -d "${APP_DIR_NAME}" ]; then
    error_message "Failed to clone repository. Directory '${APP_DIR_NAME}' not found."
    exit 1
fi
cd "${APP_PATH}"
find . -type f -print0 | xargs -0 dos2unix -q 2>/dev/null || true # Convert all files to unix line endings

log_message "Creating Python virtual environment: ${VENV_NAME}"
python3 -m venv "${VENV_NAME}" > /dev/null
PYTHON_EXEC_IN_VENV="${PWD}/${VENV_NAME}/bin/python3"
PIP_EXEC_IN_VENV="${PWD}/${VENV_NAME}/bin/pip"

log_message "Installing Python packages from requirements.txt..."
if [ ! -f "requirements.txt" ]; then
    error_message "requirements.txt not found in $(pwd)/requirements.txt."
    exit 1
fi
"${PIP_EXEC_IN_VENV}" install --upgrade pip -q --log "${WORK_DIR}/pip_upgrade.log"
"${PIP_EXEC_IN_VENV}" install -r requirements.txt -q --log "${WORK_DIR}/pip_install.log"

log_message "Ensuring 'templates/index.html' exists..."
mkdir -p templates
if [ ! -f "templates/index.html" ]; cat > templates/index.html << 'EOF'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>iDOM - Dstats</title><style>body{background-color:#080808;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol";margin:0;padding:0;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;text-align:center;overflow:hidden}.container{padding:20px 30px;border-radius:12px;background-color:rgba(20,20,20,.7);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);box-shadow:0 8px 32px 0 rgba(0,0,0,.37);border:1px solid rgba(255,255,255,.1)}h1{font-size:2.5em;color:#fff;margin-bottom:20px;font-weight:300;letter-spacing:1px}p{color:#bbb;margin-bottom:25px;font-size:1.1em}.action-button{background-color:#007bff;color:#fff;border:none;padding:12px 25px;text-align:center;text-decoration:none;display:inline-block;font-size:1em;cursor:pointer;border-radius:8px;transition:background-color .3s ease,transform .1s ease;font-weight:500;margin-top:10px}.action-button:hover{background-color:#0056b3}.action-button:active{transform:scale(.98)}.loader{border:4px solid #333;border-top:4px solid #007bff;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:20px auto}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}.discord-button{background-color:#5865F2;margin-top:15px}.discord-button:hover{background-color:#4752C4}</style></head><body><div class="container"><h1>iDOM - Dstats</h1><p id="loadingText">Loading L4 Network Statistics...</p><div class="loader" id="loaderDiv"></div><button class="action-button" id="redirectManuallyButton" style="display:none">Go to L4 Dstat Now</button> <button class="action-button discord-button" id="discordButton" style="display:none" onclick="copyDiscordLink(this)">Contact (Discord)</button></div><script type="text/javascript">const redirectDelay=3e3,l4PageUrl="/l4",discordLink="https://discord.gg/kzMdFcwC8y",redirectButton=document.getElementById("redirectManuallyButton"),discordButton=document.getElementById("discordButton"),loaderDiv=document.getElementById("loaderDiv"),loadingText=document.getElementById("loadingText");redirectButton&&(redirectButton.onclick=function(){window.location.href=l4PageUrl});function copyToClipboard(e,t){navigator.clipboard.writeText(e).then(()=>{const n=t.innerText;t.innerText="Copied!";const o=t.style.backgroundColor;t.style.backgroundColor="#28a745",setTimeout(()=>{t&&(t.innerText=n,t.style.backgroundColor=o)},1500)}).catch(e=>{alert("Failed to copy: "+err)})}function copyDiscordLink(e){copyToClipboard(discordLink,e)}setTimeout(()=>{window.location.href=l4PageUrl},redirectDelay),setTimeout(()=>{redirectButton&&(redirectButton.style.display="inline-block"),discordButton&&(discordButton.style.display="inline-block"),loaderDiv&&(loaderDiv.style.display="none"),loadingText&&(loadingText.textContent="If you were not redirected, click below:")},redirectDelay+500);</script></body></html>
EOF
fi

if command -v ufw &> /dev/null; then
    log_message "Configuring UFW for port ${WEB_APP_PORT_EXPECTED}/tcp..."
    if ! ufw status | grep -qw "${WEB_APP_PORT_EXPECTED}/tcp.*ALLOW"; then
        ufw allow "${WEB_APP_PORT_EXPECTED}/tcp" > /dev/null
        if ufw status | grep -qw "${WEB_APP_PORT_EXPECTED}/tcp.*ALLOW"; then
            log_message "UFW: Port ${WEB_APP_PORT_EXPECTED}/tcp allowed."
        else
            error_message "UFW: Failed to verify port ${WEB_APP_PORT_EXPECTED}/tcp is allowed. Please check manually."
        fi
    else
        log_message "UFW: Port ${WEB_APP_PORT_EXPECTED}/tcp already allowed."
    fi
else
    log_message "UFW not found. Manual firewall configuration for port ${WEB_APP_PORT_EXPECTED}/tcp might be needed."
fi

log_message "Starting iDOM application: ${APP_MAIN_SCRIPT}"
rm -f "${APP_NOHUP_LOG}" # Clear previous log

# Using full path to python in venv and executing in the app's directory
(cd "${PWD}" && nohup "${PYTHON_EXEC_IN_VENV}" "${APP_MAIN_SCRIPT}" > "${APP_NOHUP_LOG}" 2>&1 &)
APP_PID=$!

log_message "Waiting for application to start (PID: ${APP_PID})... Check log: ${APP_NOHUP_LOG}"
sleep 8 # Increased wait time for app to initialize and log

# Check for successful startup message from Flask/SocketIO.
# The actual message might vary slightly based on Flask/Werkzeug versions.
# Common messages: "Running on http://0.0.0.0:8000" or "Serving Flask app" or "Server listening on"
if ps -p "${APP_PID}" > /dev/null && \
   grep -Ei "(Running on http://0\.0\.0\.0:${WEB_APP_PORT_EXPECTED}|Serving Flask app.*${WEB_APP_PORT_EXPECTED}|Server listening on.*${WEB_APP_PORT_EXPECTED}|iDOM - Dstats \(L4 UDP Focus\) starting)" "${APP_NOHUP_LOG}"; then
    
    PUBLIC_IP_DETECTED=$(curl -sS --max-time 5 https://ipv4.icanhazip.com || curl -sS --max-time 5 https://api.ipify.org || echo "YOUR_SERVER_IP")
    log_message "Application started successfully."

    if [ -n "${DISCORD_WEBHOOK_URL}" ] && [ "${DISCORD_WEBHOOK_URL}" != "YOUR_DISCORD_WEBHOOK_URL_HERE" ]; then
        send_discord_notification "${PUBLIC_IP_DETECTED}" "${WEB_APP_PORT_EXPECTED}"
    fi
    
    echo "---------------------------------------------------------------------"
    echo " iDOM UDP Monitor Setup and Startup Complete!"
    echo "---------------------------------------------------------------------"
    echo " App Root:       ${PWD}"
    echo " App Log:        ${APP_NOHUP_LOG} (tail -f ${APP_NOHUP_LOG})"
    echo " Web Interface:  http://${PUBLIC_IP_DETECTED}:${WEB_APP_PORT_EXPECTED}"
    echo "---------------------------------------------------------------------"
else
    error_message "Application failed to start or confirmation message not found in log."
    if ! ps -p "${APP_PID}" > /dev/null; then
        error_message "Process with PID ${APP_PID} is not running."
    fi
    echo "--- Start of Application Log (${APP_NOHUP_LOG}) ---"
    if [ -s "${APP_NOHUP_LOG}" ]; then
        cat "${APP_NOHUP_LOG}"
    else
        echo "Log file is empty. Application likely crashed before logging."
        echo "Try running manually for detailed errors:"
        echo "cd ${PWD} && ${PYTHON_EXEC_IN_VENV} ${APP_MAIN_SCRIPT}"
    fi
    echo "--- End of Application Log ---"
    exit 1
fi

log_message "Setup script finished."
exit 0
