
# English updated to v3.3.3
All I'm trying to do is update the "install_en.sh" file in the "shell" folder.
It's not done, but it works... i think.


What I do is install the ORIGINAL mack-a's v2ray-agent from the link:

```
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh" && chmod 700 /root/install.sh && /root/install.sh
```

then, after the install of the original, replace the file with the "install_en.sh" file in the "shell" folder here. Renaming it to "install.sh" is important too...

by default the install.sh file after installation is located at /etc/v2ray-agent/install.sh

If, from the main "vasma" menu, you choose option 17 (update), it will reinstall the ORIGINAL mack-a script.


# Xray-core/sing-box one-click script quick installation

- [Thanks to JetBrains for providing non-commercial open source software development license](https://www.jetbrains.com/?from=v2ray-agent)
- [Thanks for non-commercial open source development authorization by JetBrains](https://www.jetbrains.com/?from=v2ray-agent)

- [English Version](https://github.com/mack-a/v2ray-agent/blob/master/documents/en/README_EN.md)
- [VPS purchasing guide, pitfall avoidance guide](https://www.v2ray-agent.com/archives/1679975663984)
- [TG channel](https://t.me/v2rayAgentChannel), [TG group](https://t.me/technologyshare), [official website](https://www.v2ray-agent.com/)
- [RackNerd's low-cost AS4837 packages, starting from $10 per year](https://www.v2ray-agent.com/archives/racknerdtao-can-zheng-li-nian-fu-10mei-yuan)
- [Heirloom-level Bandwagon Host (GIA, SoftBank), highly recommended](https://bandwagonhost.com/aff.php?aff=64917&pid=94)
- The ultimate package Bandwagonhost (GIA, Softbank, CMI), highly recommended. [THE PLAN v1](https://bandwagonhost.com/aff.php?aff=64917&pid=144), [THE PLAN v2](https://bandwagonhost.com/aff.php?aff=64917&pid=131)

- **Please give a ⭐ to support**

# 1. Project Introduction

## Core

-Xray-core
- sing-box

## protocol

> The following all use TLS and support multiple protocol combinations

- VLESS (Reality, Vision, TCP, WS, gRPC)
- VMess (TCP, WS)
- Trojan (TCP, gRPC)
- Hysteria2 (sing-box)
- Tuic (sing-box)
- NaiveProxy(sing-box)

## Function

- Support configuration reading between different cores
- Supports personalized installation of a single protocol
- [Support for VLESS Reality without domain name](https://www.v2ray-agent.com/archives/1708584312877)
- [Support multiple diversions for unlocking (wireguard, IPv6, Socks5, DNS, VMess (ws), SNI reverse proxy)](https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng)
- [Support batch adding of CDN nodes and automatic optimization with ClashMeta](https://www.v2ray-agent.com/archives/1684858575649)
- Supports automatic application and renewal of common certificates and wildcard certificates
- [Support subscription and multi-VPS combination subscription](https://www.v2ray-agent.com/archives/1681804748677)
- Support adding new ports in batches [only supports Xray-core]
- Support core upgrade and rollback
- Supports self-replacement of disguised sites
- Support BT download management and domain name blacklist management

# 2. Usage Guide

- [Eight-in-one script from entry to master](https://www.v2ray-agent.com/archives/1710141233)
- [Script Quick Setup Tutorial](https://www.v2ray-agent.com/archives/1682491479771)
- [The savior of junk VPS, one-click installation of the latest hysteria2 protocol](https://www.v2ray-agent.com/archives/1697162969693)
- [Tuic V5 performance improvement and usage](https://www.v2ray-agent.com/archives/1687167522196)
- [Cloudflare optimizes IP and automatically selects the fastest node tutorial](https://www.v2ray-agent.com/archives/1684858575649)
- [Notes on script usage](https://www.v2ray-agent.com/archives/1679931532764)
- [Script exception handling](https://www.v2ray-agent.com/archives/1684115970026)

# 3. Route Recommendations

- [VPS Purchase Guide, Pitfall Avoidance Guide](https://www.v2ray-agent.com/archives/1679975663984)

## 1. High-end

- [CN2 GIA](https://www.v2ray-agent.com/tags/cn2-gia)
- [AS9929](https://www.v2ray-agent.com/tags/as9929)
- [SoftBank Japan](https://www.v2ray-agent.com/tags/ruan-yin)

## 2. Cost-effectiveness

- [AS4837](https://www.v2ray-agent.com/tags/as4837)
- [CMI](https://www.v2ray-agent.com/tags/cmi)

# 4. Installation and use

## 1. Download the script

- Support shortcut startup. After installation, enter [**vasma**] in the shell to open the script. The script execution path is [**/etc/v2ray-agent/install.sh**]

- Github

```
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh" && chmod 700 /root/install.sh && /root/install.sh
```

- Official website [Backup]

```
wget -P /root -N --no-check-certificate "https://www.v2ray-agent.com/v2ray-agent/install.sh" && chmod 700 /root/install.sh && /root/install.sh
```

## 2. Usage

# 4. Feedback and Suggestions

- Submit [issue](https://github.com/mack-a/v2ray-agent/issues), [join](https://t.me/technologyshare) group chat

# 5. Donation

- Thank you for your attention and support to the open source project. If you think this project is helpful to you, you are welcome to donate through the following methods.

- [Donate by purchasing VPS](https://www.v2ray-agent.com/categories/vps)

- [Donate to me via tokens](https://www.v2ray-agent.com/1679123834836)

# 6. License

[AGPL-3.0](https://github.com/mack-a/v2ray-agent/blob/master/LICENSE)

