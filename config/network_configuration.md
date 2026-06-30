# Network & Configuration Notes

## Environment Overview

All experiments were conducted in a virtualized enterprise network built with:
- **GNS3** (Graphical Network Simulator 3) running inside VMware Workstation 16 Pro
- **4 LAN zones** with OSPF routing and 802.1Q VLAN segmentation
- **pfSense 2.7.2** as the WAN edge firewall and automated mitigation target

## Network Zones

| Zone      | Subnets                     | Router | Key Hosts                      |
|-----------|-----------------------------|--------|-------------------------------|
| LAN       | 192.168.40/50/60.0/24       | R2     | Win11 @ 192.168.50.11          |
| LAN2      | 192.168.101/110/120.0/24    | R1     | Win10 @ 192.168.101.11         |
| LAN3      | 192.168.10/20/30.0/24       | R3     | PC10, PC11, PC12               |
| LAN4      | 192.168.70/80/90.0/24       | R4     | PC7, PC8, PC9                  |
| AI Zone   | 192.168.150.0/24            | R5     | Ubuntu AI Server @ .150.10     |
| WAN/NAT   | 192.168.180.0/24            | pfSense| Kali Linux @ .180.130/.131     |

## VM Inventory

| VM                | OS Version         | IP Address          | Role                      |
|-------------------|--------------------|---------------------|---------------------------|
| GNS3vm            | Ubuntu Server      | 192.168.216.x       | GNS3 simulation engine    |
| Kali Linux 2025.2 | Debian 12-based    | 192.168.180.130/131 | Adversary node            |
| Ubuntu 24.04.3 LTS| Ubuntu LTS         | 192.168.150.10/24   | AI Defense Server         |
| Windows 10        | 10.0.19045.6332    | 192.168.101.11/24   | Secondary attack target   |
| Windows 11        | 10.0.26200.7623    | 192.168.50.11/24    | Primary attack target     |

## pfSense Firewall Notes

- **Version:** 2.7.2-RELEASE (amd64) on FreeBSD 14.0-CURRENT
- **Automated blocking:** SSH-driven `pfctl -t EasyRuleBlockHostsWAN -T add <src_ip>`
- **Block latency:** < 5 ms post-SSH-command execution
- **WAN IP:** 192.168.180.129

> ⚠️ **Security Note:** No credentials, SSH keys, or passwords are stored in this repository.
> The pfSense password in `ai_defense_orchestration.py` must be configured separately
> before deployment. See the Configuration section in the README.

## VMware Virtual Network Adapters

| VMnet   | Type      | Subnet          | Purpose               |
|---------|-----------|-----------------|-----------------------|
| VMnet1  | Host-only | 192.168.216.0   | GNS3vm management     |
| VMnet2  | Host-only | 192.168.150.0   | Ubuntu AI Server      |
| VMnet3  | Host-only | 192.168.101.0   | LAN2 — Win10          |
| VMnet4  | Host-only | 192.168.50.0    | LAN — Win11           |
| VMnet8  | NAT       | 192.168.180.0   | WAN / Internet NAT    |

## Software Versions

| Component          | Version                            |
|--------------------|------------------------------------|
| GNS3               | 2.x with GNS3vm                    |
| VMware Workstation | 16 Pro                             |
| Python             | 3.10.12                            |
| XGBoost            | 2.0.3                              |
| Scikit-learn       | 1.3.2                              |
| Scapy              | 2.5.0                              |
| Suricata           | 8.0.3 + ET Open rules              |
| Zeek               | 8.1.1                              |
| pfSense            | 2.7.2-RELEASE                      |
| Kali Linux         | 2025.2                             |
| Ubuntu             | 24.04.3 LTS                        |
