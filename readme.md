# Network Tools for NVDA

**Diagnose, monitor, and manage your network entirely from the keyboard.**

Network Tools is an [NVDA](https://www.nvaccess.org/) add-on that brings accessible, keyboard-driven network diagnostics to Windows — built for IT technicians, network administrators, and anyone who needs real network troubleshooting tools that work naturally with a screen reader, not a scaled-down version of a sighted-only utility.

## Overview

Most built-in Windows network tools (Command Prompt utilities, the Network and Sharing Center, Resource Monitor) were never designed with screen reader users in mind. Network Tools closes that gap with a single, organized menu covering the diagnostics a network professional actually needs day to day — IP configuration, DNS, Wi-Fi, connectivity testing, device discovery, firewall rules, and continuous connection monitoring — all spoken clearly by NVDA, with no visual interpretation required.

## Features

- **IP & Gateway Status** — full adapter configuration at a glance, with per-adapter tabs when more than one is active
- **DNS tools** — view current servers, find the fastest and most stable one from a fully editable server list, apply a custom DNS (with a DNS-over-HTTPS fallback for blocked networks), or test a single server on demand
- **IPv6 diagnostics** — connectivity, DNS resolution, and a combined diagnosis pinpointing whether the router or the provider is the problem
- **Wi-Fi info & password**, public IP lookup, and external IP geolocation
- **Smart Ping** (ICMP or TCP-port mode) and **Traceroute** (IPv4, IPv6, or automatic)
- **Device Scan** — discover devices on the local network, with an optional full IEEE MAC-vendor database for manufacturer identification
- **Internet Speed Test** — download/upload, latency, jitter, and packet loss via Cloudflare's public infrastructure, with parallel connections for accurate results on fast links
- **Static IP / DHCP**, **DNS repair** (flush, re-register, renew, Winsock/TCP-IP reset), and **Firewall management** (rules, port checks, per-profile status)
- **Connection Monitor** — background monitoring with live alerts, tracking latency and stability separately per network visited during the session
- **Advanced Adapter Diagnostics** via PowerShell (MTU, route metric, error counters)
- A dedicated settings panel inside NVDA's own Preferences, and full menus in **8 languages**: English, Portuguese (Brazil), Spanish, French, Italian, German, Russian, and Simplified Chinese

## Installation

**NVDA Add-on Store** (recommended, once published there): search for "Network Tools" in NVDA's Add-on Store and install directly.

**Manual installation**: download the latest `.nvda-addon` file from the [Releases](https://github.com/Guilhermeirm/nvda-network-tools/releases) page and open it — NVDA will handle the installation prompt automatically.

## Usage

Once installed, press **NVDA+Shift+R** anywhere to open the main menu, and **NVDA+Shift+C** to instantly hear the current connection status (requires the Connection Monitor to be running). Everything else is organized into a straightforward menu and submenus, navigable with the arrow keys.

This README intentionally keeps things brief — the add-on ships with a complete, in-depth guide covering every screen, field, and setting, available both in [English](https://htmlpreview.github.io/?https://github.com/Guilhermeirm/nvda-network-tools/blob/main/doc/en/readme.html) and [Portuguese](https
://htmlpreview.github.io/?https://github.com/Guilhermeirm/nvda-network-tools/blob/main/doc/pt_BR/readme.html), and directly from within NVDA (Add-ons Store → Network Tools → About).

## Compatibility

- **NVDA**: 2024.1 or later (last tested with 2026.1)
- **Windows**: 10 or later
- Core features work with zero external dependencies — only **Advanced Adapter Diagnostics** requires PowerShell to be available on the system
- An internet connection is needed for the **Speed Test**, **Find Best DNS**, and the optional **full MAC-vendor database download**; everything else works fully offline on the local network

## License

Distributed under the **GNU General Public License v2 (or later)**. See [LICENSE](LICENSE) for the full text.

## Author

Guilherme — [guilhermeirm21@gmail.com](mailto:guilhermeirm21@gmail.com)