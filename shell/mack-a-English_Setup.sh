#!/bin/bash

# Download the original install.sh
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"

# Set permissions and execute the original install.sh
chmod 700 /root/install.sh
/root/install.sh

# Rename the original install.sh to original_install.sh
mv /root/install.sh /root/original_install.sh

# Download the new install.sh and rename it
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/quartzyeti/mack-a-v2ray-agent-English/master/shell/install_en.sh"
mv /root/install_en.sh /root/install.sh

# Set permissions for the new install.sh
chmod 700 /root/install.sh
