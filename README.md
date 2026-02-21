# telnet_bruter

High-performance two-phase pipeline IoT Telnet scanner & brute-forcer written in pure C.

## Features

- **Two-phase pipeline**: Phase 1 scans for open ports, Phase 2 brute-forces credentials — both run concurrently
- **Fast epoll-based scanner**: non-blocking connect to ports 23/2323, 2-second timeout, up to 5000 concurrent connections
- **Parallel bruter**: full Telnet IAC negotiation with NAWS, up to 500 concurrent brute sessions
- **209 default credential combos**: Mirai, Hikvision, XMeye, ZTE, Huawei, GPON, Realtek and more
- **BusyBox verification**: multi-stage command chain (`enable` → `linuxshell` → `system` → `sh` → `/bin/busybox BOTNET`)
- **Zero false positives**: only devices responding with `"applet not found"` are marked as found
- **Honeypot detection**: cowrie honeypot identification ("richard" check) → `honeypots.txt`
- **Multiple input modes**: random IPs, CIDR ranges, file input, stdin
- **Bogon filtering**: skips reserved/private IP ranges
- **Thread-safe queues** with backpressure between scanner and bruter
- **Real-time stats** updated every second

## Build

```bash
make
```

## Usage

```bash
# Random IPs
./iot-bruter random <count> [scan_threads] [brute_threads]
./iot-bruter random 10000 2000 200

# CIDR range
./iot-bruter range 192.168.1.0/24

# Ranges from file (one CIDR per line)
./iot-bruter file ranges.txt 2000 200

# IPs from stdin
cat ips.txt | ./iot-bruter stdin 1000 200
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `count` | Number of random IPs to generate | required for `random` mode |
| `scan_threads` | Number of scanner threads | 1000 |
| `brute_threads` | Number of bruter threads | 200 |

## How It Works

### Phase 1 — Scanner
- Generates or reads target IPs
- Fast non-blocking TCP connect to ports 23 and 2323
- 2-second connection timeout
- Open ports are pushed to the brute queue

### Phase 2 — Bruter
- Receives confirmed open ports from scanner in real-time
- Full Telnet IAC negotiation (DO/WILL/WONT/DONT + NAWS window size)
- Tries 209 credential combinations per target
- On successful login, runs verification chain:
  1. `enable`
  2. `linuxshell`
  3. `system`
  4. `sh`
  5. `/bin/busybox BOTNET`
- Only `"applet not found"` response = confirmed IoT device with BusyBox
- Detects cowrie honeypots and logs them separately

### State Machine

```
CONNECT → IAC → WAIT_PROMPT → SENT_USER → SENT_PASS → SEND_ENABLE →
SEND_LINUXSHELL → SEND_SYSTEM → SEND_SH → SEND_BUSYBOX → WAIT_TOKEN
```

## Output

### Stats (every second)
```
[5s] scan:5000/1000 open:15 | brute:15/0 found:2 failed:10 hp:0 | sq:500 bq:3
      ^total ^active ^open    ^active ^queued ^found ^failed ^hp  ^scan_q ^brute_q
```

### Files
- `found.txt` — BusyBox-verified devices: `ip:port user:pass`
- `honeypots.txt` — detected honeypots: `ip:port user:pass`

## Project Structure

```
├── main.c          # CLI, thread orchestration, IP generation, stats
├── scanner.c       # Epoll-based port scanner
├── bruter.c        # Telnet bruter with IAC + BusyBox verification
├── combos.c        # 209 default credential pairs
├── queue.c         # Thread-safe scan/brute queues
├── include/
│   ├── config.h    # Constants and limits
│   ├── bruter.h    # Bruter types and API
│   ├── scanner.h   # Scanner API
│   ├── combos.h    # Combo types
│   └── queue.h     # Queue types and API
├── Makefile
└── ranges.txt      # Sample IoT IP ranges
```

## Credentials

209 built-in credential pairs covering:
- Default root/admin passwords (empty, 123456, password, admin, etc.)
- Mirai botnet originals (xc3511, vizxv, xmhdipc, 7ujMko0vizxv, etc.)
- Camera vendors (Hikvision, XMeye, vstarcam, ipcam)
- Router/modem vendors (ZTE, Huawei, GPON, Realtek, Broadcom, Netgear)
- Telecom defaults (telecomadmin, bayandsl, ttnet)
- Linux/embedded (pi/raspberry, ubnt, ubuntu)

## Requirements

- Linux (epoll-based, will not work on macOS/Windows)
- GCC
- pthreads

## Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning or testing any network or device.
