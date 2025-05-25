#!/bin/bash
set -e
set -o pipefail

DEFAULT_WORK_DIR="/tmp/dstatubuntu"
REPO_URL="https://github.com/umbx-dot/udstat.git"
VENV_NAME="venv"
APP_MAIN_SCRIPT="app.py"
WEB_APP_PORT_EXPECTED=8000
MONITORED_UDP_PORT_EXPECTED=53

log_message() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"
}

error_message() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_message "Starting iDOM UDP Monitor Advanced Setup..."

if [ "$(id -u)" -ne 0 ]; then
    error_message "This script must be run as root. Please use 'sudo bash ${0}' or 'curl ... | sudo bash'."
    exit 1
fi

WORK_DIR="${1:-${DEFAULT_WORK_DIR}}"
APP_DIR_NAME=$(basename "${REPO_URL}" .git)
APP_PATH="${WORK_DIR}/${APP_DIR_NAME}"
APP_NOHUP_LOG="${WORK_DIR}/idom_app_nohup.log"

log_message "Working directory set to: ${WORK_DIR}"
log_message "Application will be cloned into: ${APP_PATH}"
log_message "Application nohup log will be at: ${APP_NOHUP_LOG}"

log_message "Preparing working directory..."
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

if [ -d "${APP_DIR_NAME}" ]; then
    log_message "Found existing application directory '${APP_DIR_NAME}'. Attempting to clean up."
    if [ -f "${APP_PATH}/${VENV_NAME}/bin/python3" ]; then
        log_message "Attempting to stop existing application process from ${APP_PATH}..."
        pkill -f "${APP_PATH}/${VENV_NAME}/bin/python3 ${APP_MAIN_SCRIPT}" || true
        sleep 2
    fi
    log_message "Removing old application directory: ${APP_PATH}"
    rm -rf "${APP_DIR_NAME}"
fi

log_message "Updating package list and installing system dependencies (git, python3, python3-pip, python3-venv, curl)..."
apt-get update -y
apt-get install -y git python3 python3-pip python3-venv curl

log_message "Cloning repository from ${REPO_URL} into ${WORK_DIR}..."
git clone "${REPO_URL}"
if [ ! -d "${APP_DIR_NAME}" ]; then
    error_message "Failed to clone repository. Directory '${APP_DIR_NAME}' not found after clone."
    exit 1
fi
cd "${APP_PATH}"
log_message "Successfully cloned repository. Current directory: $(pwd)"

log_message "Creating Python virtual environment '${VENV_NAME}'..."
python3 -m venv "${VENV_NAME}"

log_message "Activating virtual environment and installing Python packages from requirements.txt..."
PYTHON_EXEC_IN_VENV="${PWD}/${VENV_NAME}/bin/python3"
PIP_EXEC_IN_VENV="${PWD}/${VENV_NAME}/bin/pip"

if [ ! -f "requirements.txt" ]; then
    error_message "requirements.txt not found in the repository at $(pwd)/requirements.txt."
    exit 1
fi

"${PIP_EXEC_IN_VENV}" install --upgrade pip
"${PIP_EXEC_IN_VENV}" install -r requirements.txt
log_message "Python packages installed successfully."

log_message "Ensuring 'templates/index.html' exists for the main page..."
mkdir -p templates
if [ ! -f "templates/index.html" ]; then
    log_message "Creating 'templates/index.html'..."
    cat > templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iDOM - Dstats</title>
    <style>
        body {
            background-color: #080808;
            color: #e0e0e0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            text-align: center;
            overflow: hidden;
        }
        .container {
            padding: 20px 30px;
            border-radius: 12px;
            background-color: rgba(20, 20, 20, 0.7);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        h1 {
            font-size: 2.5em;
            color: #ffffff;
            margin-bottom: 20px;
            font-weight: 300;
            letter-spacing: 1px;
        }
        p {
            color: #bbbbbb;
            margin-bottom: 25px;
            font-size: 1.1em;
        }
        .action-button {
            background-color: #007bff;
            color: #ffffff;
            border: none;
            padding: 12px 25px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 1em;
            cursor: pointer;
            border-radius: 8px;
            transition: background-color 0.3s ease, transform 0.1s ease;
            font-weight: 500;
            margin-top: 10px;
        }
        .action-button:hover {
            background-color: #0056b3;
        }
        .action-button:active {
            transform: scale(0.98);
        }
        .loader {
            border: 4px solid #333;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .discord-button {
            background-color: #5865F2;
            margin-top: 15px;
        }
        .discord-button:hover {
            background-color: #4752C4;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>iDOM - Dstats</h1>
        <p id="loadingText">Loading L4 Network Statistics...</p>
        <div class="loader" id="loaderDiv"></div>
        <button class="action-button" id="redirectManuallyButton" style="display: none;">Go to L4 Dstat Now</button>
        <button class="action-button discord-button" id="discordButton" style="display: none;" onclick="copyDiscordLink(this)">Contact (Discord)</button>
    </div>

    <script type="text/javascript">
        const redirectDelay = 3000; 
        const l4PageUrl = "/l4";
        const discordLink = 'https://discord.gg/kzMdFcwC8y';

        const redirectButton = document.getElementById('redirectManuallyButton');
        const discordButton = document.getElementById('discordButton');
        const loaderDiv = document.getElementById('loaderDiv');
        const loadingText = document.getElementById('loadingText');

        if(redirectButton) redirectButton.onclick = function() { window.location.href = l4PageUrl; };

        function copyToClipboard(text, buttonElement) {
            navigator.clipboard.writeText(text).then(() => {
                const originalText = buttonElement.innerText;
                buttonElement.innerText = 'Copied!';
                const originalBg = buttonElement.style.backgroundColor;
                buttonElement.style.backgroundColor = '#28a745';
                setTimeout(() => {
                    if (buttonElement) { 
                        buttonElement.innerText = originalText;
                        buttonElement.style.backgroundColor = originalBg;
                    }
                }, 1500);
            }).catch(err => {
                alert('Failed to copy: ' + err);
            });
        }

        function copyDiscordLink(buttonElement) {
            copyToClipboard(discordLink, buttonElement);
        }

        setTimeout(() => {
            window.location.href = l4PageUrl;
        }, redirectDelay);

        setTimeout(() => {
            if (redirectButton) redirectButton.style.display = 'inline-block';
            if (discordButton) discordButton.style.display = 'inline-block';
            if (loaderDiv) loaderDiv.style.display = 'none';
            if (loadingText) loadingText.textContent = "If you were not redirected, click below:"
        }, redirectDelay + 500); 
    </script>
</body>
</html>
EOF
    log_message "'templates/index.html' created/verified."
else
    log_message "'templates/index.html' already exists. Skipping creation."
fi

if command -v ufw &> /dev/null; then
    log_message "UFW detected. Attempting to allow port ${WEB_APP_PORT_EXPECTED}/tcp..."
    if ufw status | grep -qw "${WEB_APP_PORT_EXPECTED}/tcp.*ALLOW"; then
        log_message "Port ${WEB_APP_PORT_EXPECTED}/tcp is already allowed in UFW."
    else
        ufw allow "${WEB_APP_PORT_EXPECTED}/tcp"
        if ufw status | grep -qw "${WEB_APP_PORT_EXPECTED}/tcp.*ALLOW"; then
            log_message "Port ${WEB_APP_PORT_EXPECTED}/tcp allowed in UFW successfully."
        else
            error_message "Failed to automatically allow port ${WEB_APP_PORT_EXPECTED}/tcp in UFW. Please do it manually (e.g., sudo ufw allow ${WEB_APP_PORT_EXPECTED}/tcp)."
        fi
    fi
else
    log_message "UFW not found. Please ensure port ${WEB_APP_PORT_EXPECTED}/tcp is open in your firewall manually."
fi

log_message "Starting the iDOM application (${APP_MAIN_SCRIPT}) in the background..."
log_message "Application output will be logged to: ${APP_NOHUP_LOG}"

if [ ! -f "${APP_MAIN_SCRIPT}" ]; then
    error_message "Main application script '${APP_MAIN_SCRIPT}' not found in $(pwd)."
    exit 1
fi

log_message "Final check to stop any other instances running from this exact path..."
pkill -f "${PYTHON_EXEC_IN_VENV} ${APP_MAIN_SCRIPT}" || true
sleep 1

nohup "${PYTHON_EXEC_IN_VENV}" "${APP_MAIN_SCRIPT}" > "${APP_NOHUP_LOG}" 2>&1 &
APP_PID=$!

sleep 4

if ps -p "${APP_PID}" > /dev/null && \
   ( [ -s "${APP_NOHUP_LOG}" ] && grep -q "Running as root on Ubuntu." "${APP_NOHUP_LOG}" ); then
    
    log_message "Application started successfully with PID ${APP_PID}."
    PUBLIC_IP_DETECTED=$(curl -sS --max-time 5 https://ipv4.icanhazip.com || curl -sS --max-time 5 https://api.ipify.org || curl -sS --max-time 5 https://checkip.amazonaws.com || echo "YOUR_SERVER_IP (Detection failed)")
    
    echo ""
    echo "---------------------------------------------------------------------"
    echo " iDOM UDP Monitor Setup and Startup Complete!                      "
    echo "---------------------------------------------------------------------"
    echo " Application Root:      ${PWD}"
    echo " Virtual Environment:   ${PWD}/${VENV_NAME}"
    echo " Application Log:       ${APP_NOHUP_LOG}"
    echo "                        View with: tail -f ${APP_NOHUP_LOG}"
    echo ""
    echo " Web Interface:         http://${PUBLIC_IP_DETECTED}:${WEB_APP_PORT_EXPECTED}"
    echo " Monitored UDP Port:    ${MONITORED_UDP_PORT_EXPECTED} (as per app.py)"
    echo ""
    echo " To stop the application (from any directory):"
    echo "   sudo pkill -f \"${PYTHON_EXEC_IN_VENV} ${APP_MAIN_SCRIPT}\""
    echo "   (The above targets the specific python interpreter and script path)"
    echo " Or find PID with 'pgrep -af \"${APP_MAIN_SCRIPT}\"' and use 'sudo kill <PID>'"
    echo "---------------------------------------------------------------------"
else
    error_message "Application failed to start or did not confirm successful startup via log message."
    error_message "Please check the log for details: ${APP_NOHUP_LOG}"
    echo ""
    echo "--- Start of Application Log (${APP_NOHUP_LOG}) ---"
    if [ -s "${APP_NOHUP_LOG}" ]; then
        cat "${APP_NOHUP_LOG}"
    else
        echo "Log file is empty or unreadable. The application might have crashed very early."
        echo "Possible reasons: Permissions, port already in use, missing critical dependency not caught earlier."
    fi
    echo "--- End of Application Log ---"
    exit 1
fi

log_message "Setup script finished successfully."
exit 0