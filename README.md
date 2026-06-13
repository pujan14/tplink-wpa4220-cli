# tplink-wpa4220-cli

A minimal Python CLI to query and control the **TP-Link TL-WPA4220** (AV600 300Mbps Wi-Fi Powerline Extender) — no dependencies, no install, single file.

```
$ python3 tplink_wpa.py info

Device MAC (Ethernet) : 36-03-f2-40-e0-72

Powerline adapter:
  Local PLC MAC  : f0-09-0d-df-fb-29
  Network name   : MyNetwork
  Powerline key  : XXXX-XXXX-XXXX-XXXX
  Neighbor F0-09-0D-E0-08-D5 : TX=273 Mbps, RX=220 Mbps

Connected devices:
  192.168.88.1
```

## Requirements

- Python 3.6+
- `ping` (standard on all platforms)
- Same LAN as the router

No pip packages needed.

## Installation

Download the single script:

```sh
curl -O https://raw.githubusercontent.com/pujan14/tplink-wpa4220-cli/main/tplink_wpa.py
```

Or clone:

```sh
git clone https://github.com/pujan14/tplink-wpa4220-cli.git
cd tplink-wpa4220-cli
```

## Configuration

Open `tplink_wpa.py` and update the two constants near the top to match your device:

```python
ROUTER_MAC     = "f0:09:0d:df:fb:28"   # MAC address printed on the router label
ROUTER_LAST_IP = "192.168.88.252"       # last known IP — used as a fast-path hint
```

The script tries the last-known IP first. If that fails, it scans the ARP table by MAC address — so it keeps working even after a DHCP lease change.

### Finding your router's MAC

It's printed on the label on the bottom of the device, or visible in your router/DHCP server's client list.

## Finding the admin password

TP-Link's web UI stores the admin password in `localStorage['lgkey']` after each login:

1. Open the router's web UI in Chrome and log in
2. Open DevTools → Console and run:
   ```js
   localStorage.getItem('lgkey')
   ```
3. Use the returned string as `<password>` below

> **Note:** The password is **not** the powerline network name (NetworkName) shown in the UI — that's a different field.

## Usage

```sh
python3 tplink_wpa.py <password> [command]
```

Or use a password file to keep it out of process listings and shell history:

```sh
echo 'yourpassword' > ~/.tplink_pass
chmod 600 ~/.tplink_pass
python3 tplink_wpa.py --password-file ~/.tplink_pass [command]
```

Or via environment variable:

```sh
export TPLINK_PASSWORD=yourpassword
python3 tplink_wpa.py [command]
```

### Commands

| Command | Description |
|---|---|
| `info` | Device MAC, powerline network, neighbor link speeds, connected IPs (default) |
| `devices` | List IPs of all connected devices |
| `plc` | Powerline adapter info and TX/RX speeds to neighbours |
| `reboot` | Reboot the device, waits up to 120s for it to come back |
| `raw <code> [body]` | Raw TDDP API call — prints the response body |

### Examples

```sh
# Full info
python3 tplink_wpa.py mypassword info

# Powerline speeds only
python3 tplink_wpa.py mypassword plc

# Reboot and wait for it to come back
python3 tplink_wpa.py mypassword reboot

# Raw API call
python3 tplink_wpa.py mypassword raw 2 "121|1,0,0"
```

## Running on a Linux server / cron

### Prerequisites

Python 3 and `ping` are all that's needed. On Linux the script reads `/proc/net/arp` directly — no `arp` command, no root required.

Verify before setting up cron:

```sh
ping -c 1 -W 1 <router-ip>
python3 tplink_wpa.py info
```

### Secure password setup

Store the password in a file readable only by your user:

```sh
echo 'yourpassword' > ~/.tplink_pass
chmod 600 ~/.tplink_pass
```

### Crontab

```
crontab -e
```

```cron
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Log device info every 5 minutes
*/5 * * * * python3 /home/ps/tplink_wpa.py --password-file /home/ps/.tplink_pass info >> /var/log/tplink.log 2>&1

# Nightly reboot at 3 AM
0 3 * * * python3 /home/ps/tplink_wpa.py --password-file /home/ps/.tplink_pass reboot >> /var/log/tplink.log 2>&1
```

> The `PATH` line is required — cron uses a minimal environment and may not find `ping` otherwise.

> If `ping` requires root on your system, the script skips the ARP warm-up and reads `/proc/net/arp` directly. This still works as long as the router has been seen recently.

## Protocol notes (TDDP)

The TL-WPA4220 uses TP-Link's proprietary **TDDP** (TP-Link Device Debug Protocol) — an HTTP-based API where the session is bound to the TCP connection.

### Auth flow

1. `POST /?code=7&asyn=0&id=!` → HTTP 401 with a challenge (`n_str` + `lookup` table)
2. Compute `su_encrypt(n_str, password, lookup)` — an XOR cipher from the router's JS
3. `POST /?code=7&asyn=0&id=<encrypted>` on the **same socket** → HTTP 200

All subsequent requests carry the session token as `?id=`.

### API codes

| Code | Name | Description |
|---|---|---|
| 0 | INSTRUCT | Run a shell command |
| 2 | BLOCK_READ | Read a config block (`<id>\|1,0,0`) |
| 5 | **RESET** | **Factory reset — erases everything. Do not use.** |
| 6 | REBOOT | Reboot the device |
| 7 | AUTH | Login challenge/response |
| 8 | GETPEERMAC | Returns the connecting client's MAC |
| 11 | LOGOUT | End session |

### Config blocks

| Block | Contents |
|---|---|
| 13 | Connected device IPs |
| 121 | Powerline info — local PLC MAC, network name, powerline key |
