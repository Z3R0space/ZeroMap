<div align="center">

```
  ███████╗███████╗██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗
     ███╔╝██╔════╝██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
    ███╔╝ █████╗  ██████╔╝██║   ██║██╔████╔██║███████║██████╔╝
   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝
███████╗███████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
```

**Godspeed Edition**

*Nmap slow? Ewww... · Rustscan who? · Your firewall called. It's scared.*

![Platform](https://img.shields.io/badge/platform-Linux-blue?style=flat-square)
![Language](https://img.shields.io/badge/language-C-orange?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Root](https://img.shields.io/badge/requires-root-red?style=flat-square)

</div>

---

ZeroMap is a high-speed, multi-threaded TCP port scanner written in C. It crafts raw packets at the Ethernet layer using `AF_PACKET` sockets — no libpcap, no nmap wrappers, just raw syscalls. It supports seven scan modes, combinable decoy bursts, IP fragmentation, slow-rate evasion, passive Shodan lookups, and multi-target file scanning.

**Problem**: As an experienced red-teamer, I witnessed the problem with port scanning phase, where we have to utilize multiple tools to hide our scans, ad sometimes it is very time-taking.
**Solution**: I developed a C-based Port Scanner, which is as fast as Masscan and has stealth capabilities like Nmap, integrating the speed and stealth makes it a perfect choice for red teaming or initial scans, and it also includes a unique scan type which major port scanners lack on - a passive scan type which utilizes shodan to discover ports and services on the target, with 0 active interaction which results into 0 detection.

> **Legal notice:** Only scan hosts and networks you own or have explicit written permission to test. Unauthorized port scanning is illegal in most jurisdictions.

---

## Features

- **Seven scan modes** — SYN, FIN, NULL, XMAS, Fragmented, Slow, and Decoy
- **Raw packet crafting** at Layer 2 via `AF_PACKET` — no kernel TCP stack involved
- **Multi-threaded TX** with `sendmmsg` batch sending for maximum throughput
- **Combinable `--decoy`** flag works alongside any scan mode
- **Passive Shodan integration** — query the Shodan API without sending a single packet to the target
- **Port range filtering** — scan a single port, a range, or all 65535
- **Multi-target scanning** via `--file` with commented IP lists
- **Automatic retry pass** for ports that received no reply
- **Stealth post-processing** — correctly classifies `OPEN | FILTERED` in FIN/NULL/XMAS modes

---

## Requirements

### System

- Linux (kernel 3.x+)
- Root / `CAP_NET_RAW` privileges
- GCC

### Libraries

```bash
sudo apt install libcurl4-openssl-dev libcjson-dev
```

| Library | Used for |
|---|---|
| `libcurl` | Shodan API HTTP requests (`--shodan`) |
| `libcjson` | Parsing Shodan JSON responses |
| `libpthread` | Multi-threaded TX/RX |

> If you don't plan to use `--shodan`, the tool still compiles fine with both libraries installed — they just won't be exercised.

---

## Installation

```bash
git clone https://github.com/yourname/zeromap.git
cd zeromap

# Install dependencies
sudo apt install libcurl4-openssl-dev libcjson-dev

# Or manually
gcc -O2 -Wall -D_GNU_SOURCE -o scanner main.c scanner.c -lpthread -lcurl -lcjson
```

### Shodan API key (optional)

If you want to use `--shodan`, open `scanner.h` and replace the placeholder with your key from [account.shodan.io](https://account.shodan.io/):

```c
#define SHODAN_API_KEY  "your_actual_key_here"
```

### Interface name

By default ZeroMap uses `ens33`. If your interface is different (`eth0`, `wlan0`, etc.), change the define in `scanner.h`:

```c
#define IFACE  "eth0"
```

---

## Usage

```
Usage:
  sudo ./scanner <target-IP> [--ports <range>] [--mode] [--decoy] [--shodan]
  sudo ./scanner --file <targets.txt> [--ports <range>] [--mode] [--decoy] [--shodan]
```

### Options

| Option | Description |
|---|---|
| `<target-IP>` | Single target to scan |
| `--file <path>` | File containing one IP per line |
| `--ports <range>` | Port range: `80`, `1-1024`, `8000-9000` (default: all) |
| `--syn` | SYN (half-open) scan — default |
| `--fin` | FIN scan |
| `--null` | NULL scan (no TCP flags) |
| `--xmas` | XMAS scan (FIN + PSH + URG) |
| `--frag` | Fragmented SYN scan |
| `--slow` | Slow SYN scan with random delays |
| `--decoy` | Fire spoofed-IP burst before the real scan (combinable) |
| `--shodan` | Passive Shodan lookup only — zero packets sent to target |

---

## Examples

```bash
# Default SYN scan — all ports
sudo ./scanner 192.168.1.1

# Scan only the first 1024 ports
sudo ./scanner 192.168.1.1 --ports 1-1024

# XMAS scan on a port range
sudo ./scanner 192.168.1.1 --ports 1-1024 --xmas

# SYN scan with a decoy burst to bury your real IP
sudo ./scanner 192.168.1.1 --decoy

# Combine any mode with decoy
sudo ./scanner 192.168.1.1 --slow --decoy --ports 1-500
sudo ./scanner 192.168.1.1 --xmas --decoy

# Passive Shodan lookup (no packets sent to target)
sudo ./scanner 192.168.1.1 --shodan
sudo ./scanner 192.168.1.1 --shodan --ports 1-1024

# Scan multiple targets from a file
sudo ./scanner --file targets.txt
sudo ./scanner --file targets.txt --ports 1-1024 --syn --decoy
sudo ./scanner --file targets.txt --shodan
```

---

## Scan Modes Explained

### SYN scan (default)
Sends a SYN packet and waits for the response. A `SYN+ACK` reply means the port is open; an `RST` means closed. The connection is never completed — hence "half-open." Fast, stealthy, and the go-to for most situations.

### FIN scan (`--fin`)
Sends a FIN packet instead of SYN. On RFC-793-compliant stacks (Linux, BSD), a closed port replies with `RST` and an open port stays silent. Does **not** work against Windows targets, which reply with `RST` for everything regardless.

### NULL scan (`--null`)
Sends a packet with no TCP flags set at all. Detection logic is identical to FIN — silence means open, `RST` means closed. Useful for evading simple rule-based firewalls that only inspect flag combinations.

### XMAS scan (`--xmas`)
Sets FIN, PSH, and URG simultaneously — lights the packet up like a Christmas tree. Same open/closed detection logic as FIN and NULL.

### Fragmented SYN (`--frag`)
Splits a single SYN across two IP fragments. Older stateless firewalls that only inspect the first fragment may pass both fragments through, allowing the target's TCP stack to reassemble and respond.

### Slow scan (`--slow`)
Sends SYNs with randomised inter-packet delays between 5ms and 50ms. Designed to stay below the threshold of rate-based IDS systems that trigger on burst traffic patterns.

### Decoy burst (`--decoy`)
Before running the actual scan, ZeroMap sends 100 spoofed SYN packets from each of 5 hardcoded fake IPs. This floods the target's connection log with noise, making your real IP harder to identify. Decoy is a **flag**, not a mode — combine it with any scan type:

```bash
sudo ./scanner 10.0.0.1 --xmas --decoy --ports 1-1024
```

### Shodan passive scan (`--shodan`)
Queries the Shodan API for the target IP. Returns known open ports, service banners, product versions, OS fingerprint, organisation, ISP, hostnames, and CVEs — all without sending a single packet to the target. Requires a valid Shodan API key in `scanner.h`.

---

## Multi-Target File Format

```
# Web servers
192.168.1.1
192.168.1.2

# Database hosts
10.0.0.10
10.0.0.11

# Leave blank lines wherever you like
172.16.0.99
```

- One IP per line
- `#` starts a comment — the rest of the line is ignored
- Blank lines are ignored
- All flags (`--ports`, `--mode`, `--decoy`, `--shodan`) apply to every target in the file

---

## Output

```
[OPEN]          22  - ssh
[OPEN]          80  - http
[OPEN]         443  - https
[OPEN|FILTERED] 8080 - http-alt   ← stealth modes only
```

For Shodan mode:

```
[SHODAN] ── Host info ──────────────────────────────────────
[SHODAN]  Organization : Cloudflare, Inc.
[SHODAN]  ISP          : Cloudflare
[SHODAN]  OS           : N/A
[SHODAN]  Country      : United States

[SHODAN] ── Service details ─────────────────────────────────
Port    Transport  Product              Banner
------  ---------  -------------------  ------
80      tcp        nginx 1.21.0         HTTP/1.1 200 OK ...
443     tcp        nginx 1.21.0         ...
```

---

## Configuration

All tunables live in `scanner.h`:

| Define | Default | Description |
|---|---|---|
| `IFACE` | `ens33` | Network interface to use |
| `SRC_PORT` | `54321` | Source port for all outgoing packets |
| `TX_THREADS` | `4` | Number of parallel TX threads |
| `BATCH_SIZE` | `64` | Packets per `sendmmsg` batch |
| `RX_GRACE` | `2` | Seconds to keep receiving after TX completes |
| `MAX_RETRIES` | `1` | Number of retry passes for unanswered ports |
| `RETRY_DELAY_MS` | `800` | Delay before retry pass (ms) |
| `SLOW_MIN_DELAY_US` | `5000` | Minimum inter-packet delay in slow mode (µs) |
| `SLOW_MAX_DELAY_US` | `50000` | Maximum inter-packet delay in slow mode (µs) |
| `MAX_DECOYS` | `5` | Number of fake IPs in decoy burst |
| `SHODAN_API_KEY` | *(placeholder)* | Your Shodan API key |

---

## How It Works

ZeroMap bypasses the kernel's TCP stack entirely by opening `AF_PACKET` raw sockets at Layer 2. It constructs complete Ethernet + IP + TCP headers from scratch, computes checksums manually, and sends packets in large batches using `sendmmsg` for throughput. A dedicated RX thread captures replies using a second `AF_PACKET` socket with a large receive buffer and busy-poll enabled to minimise latency.

```
  ┌─────────────┐     TX threads (x4)      ┌──────────────┐
  │  main()     │──── raw SYN packets ────▶│   Target     │
  │             │                           │              │
  │             │◀─── SYN+ACK / RST ───────│              │
  │  RX thread  │                           └──────────────┘
  └─────────────┘
        │
        ▼
  open_ports[] / closed_ports[] / syn_sent[]
        │
        ▼
  Retry pass → stealth post-processing → results
```

---

## Project Structure

```
zeromap/
├── scanner.h      # Configuration, structs, public API
├── scanner.c      # Packet crafting, TX/RX threads, Shodan
├── main.c         # Argument parsing, scan orchestration
```

---

## Limitations

- **Linux only** — uses `AF_PACKET`, `sendmmsg`, and `/proc` ARP; not portable to macOS or BSD
- **Root required** — raw sockets require `CAP_NET_RAW`
- **IPv4 only** — no IPv6 support
- **FIN / NULL / XMAS do not work against Windows** — Windows replies with RST for all closed and open ports, making stealth mode results unreliable
- **Shodan requires an internet connection and a paid/free API key**
- **Decoy IPs are hardcoded** in `scanner.h` — edit `DECOY_IPS[]` to use your own

---

## License

MIT — see `LICENSE` for details.
