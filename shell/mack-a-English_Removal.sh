#!/bin/bash

# Rename the current install.sh to install_en.sh
mv /root/install.sh /root/install_en.sh

# Rename original_install.sh back to install.sh
mv /root/original_install.sh /root/install.sh

# Set permissions for the renamed install.sh
chmod 700 /root/install.sh
