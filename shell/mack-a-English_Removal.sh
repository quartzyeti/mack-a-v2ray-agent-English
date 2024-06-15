#!/bin/bash

# Rename the current install.sh to install_en.sh
mv /etc/v2ray-agent/install.sh /etc/v2ray-agent/install_en.sh

# Rename original_install.sh back to install.sh
mv /etc/v2ray-agent/original_install.sh /etc/v2ray-agent/install.sh

# Set permissions for the renamed install.sh
chmod 700 /etc/v2ray-agent/install.sh
