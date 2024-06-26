#!/bin/bash

# Download the Original install.sh
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"

# Set permissions for the original install.sh
chmod 700 /root/install.sh

# Execute the original install.sh in the background
/root/install.sh &

# Give it some time to execute and bring up the menu (adjust the sleep duration as needed)
sleep 1

# Find the process ID (PID) of the install.sh script and kill it
pkill -f /root/install.sh

# Rename the original install.sh to original_install.sh
mv /etc/v2ray-agent/install.sh /etc/v2ray-agent/original_install.sh

# Download the new install.sh and rename it
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/quartzyeti/mack-a-v2ray-agent-English/master/shell/install_en.sh"
mv /root/install_en.sh /etc/v2ray-agent/install.sh

# Set permissions for the new install.sh
chmod 700 /etc/v2ray-agent/install.sh && /etc/v2ray-agent/install.sh

# Remove the English_Setup.sh script
rm -- "$0"
