#!/usr/bin/env python3
"""
TL-WPA4220 CLI — login and query the router via its TDDP protocol.

Usage:
    python3 tplink_wpa.py <password> [command] [args...]
    python3 tplink_wpa.py --password-file <path> [command] [args...]
    TPLINK_PASSWORD=<password> python3 tplink_wpa.py [command] [args...]

Commands (default: info):
    info              — device info and powerline network
    devices           — connected device IPs
    plc               — powerline link status
    reboot            — reboot the router (waits for it to come back)
    raw <code> [body] — raw API call

The session/challenge is bound to the TCP connection; we use a persistent
keep-alive socket so the login and all subsequent requests share one session.
"""

import os
import socket
import subprocess
import sys
import time

# Router identity — MAC is stable across reboots/DHCP changes; last known IP is a fast-path hint
ROUTER_MAC = "f0:09:0d:df:fb:28"
ROUTER_LAST_IP = "192.168.88.252"
PORT = 80


# ── Host discovery ────────────────────────────────────────────────────────────

def _mac_canonical(mac: str) -> str:
    """Normalise MAC to zero-padded lowercase colon format: f0:09:0d:df:fb:28"""
    parts = mac.lower().replace("-", ":").replace(".", ":").split(":")
    return ":".join(p.zfill(2) for p in parts)


def _reachable(ip: str, port: int = PORT, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except OSError:
        return False


def find_host(mac: str = ROUTER_MAC, last_ip: str = ROUTER_LAST_IP,
              scan_timeout: int = 30) -> str:
    """
    Return the router's current IP.
    1. Try last known IP first (fast path).
    2. Fall back to ARP-table scan by MAC address.
    """
    if last_ip and _reachable(last_ip):
        return last_ip

    print(f"[warn] {last_ip} not reachable, scanning ARP table for {mac}...")
    return _find_by_mac(mac, timeout=scan_timeout)


def _arp_table() -> str:
    # Linux: /proc/net/arp is readable without root
    try:
        with open("/proc/net/arp") as f:
            return f.read()
    except OSError:
        pass
    # macOS / fallback
    try:
        return subprocess.check_output(["arp", "-an"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""


def _find_by_mac(mac: str, timeout: int = 30) -> str:
    """Scan ARP table, pinging the subnet first to populate it."""
    target = _mac_canonical(mac)
    local = _local_ip()
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Ping a few hosts in the subnet to refresh ARP entries
        if local:
            prefix = local.rsplit(".", 1)[0]
            for last in (1, 252, 253, 254, 255):
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", f"{prefix}.{last}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
        out = _arp_table()
        for line in out.splitlines():
            # Normalise MAC tokens in the ARP line and compare
            for token in line.split():
                token = token.strip("()")
                if ":" in token and _mac_canonical(token) == target:
                    # Extract IP from the same line
                    for part in line.split():
                        part = part.strip("()")
                        if part.count(".") == 3:
                            try:
                                socket.inet_aton(part)
                                return part
                            except OSError:
                                pass
        time.sleep(2)
    raise RuntimeError(f"Could not find IP for MAC {mac} after {timeout}s")


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


# ── HTTP over a persistent TCP socket ────────────────────────────────────────

class PersistentHTTP:
    def __init__(self, host, port=80, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock = None

    def _connect(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        self._sock = s

    def post(self, path, body=""):
        if not self._sock:
            self._connect()

        body_bytes = body.encode() if isinstance(body, str) else body
        hdrs = {
            "Host": self.host,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15",
            "Accept": "text/plain, */*; q=0.01",
            "Content-Type": "text/plain;charset=UTF-8",
            "Content-Length": str(len(body_bytes)),
            "Origin": f"http://{self.host}",
            "Referer": f"http://{self.host}/",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "keep-alive",
        }
        raw = f"POST {path} HTTP/1.1\r\n"
        for k, v in hdrs.items():
            raw += f"{k}: {v}\r\n"
        raw += "\r\n"
        request = raw.encode() + body_bytes

        try:
            self._sock.sendall(request)
            return self._read_response()
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Reconnect once on broken pipe
            self._connect()
            self._sock.sendall(request)
            return self._read_response()

    def _read_response(self):
        data = b""
        self._sock.settimeout(5)
        while True:
            try:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    header_end = data.index(b"\r\n\r\n") + 4
                    cl = 0
                    for line in data[:header_end].decode(errors="replace").splitlines():
                        if line.lower().startswith("content-length:"):
                            cl = int(line.split(":", 1)[1].strip())
                    if len(data) >= header_end + cl:
                        break
            except socket.timeout:
                break
        if b"\r\n\r\n" in data:
            header_part, body_part = data.split(b"\r\n\r\n", 1)
            try:
                status = int(header_part.split(b"\r\n")[0].split()[1])
            except Exception:
                status = 0
            return status, body_part.decode(errors="replace")
        return 0, data.decode(errors="replace")

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None


# ── TP-Link TDDP auth cipher ─────────────────────────────────────────────────

def su_encrypt(key: str, password: str, lookup: str) -> str:
    """
    Replicates $.su.encrypt(key, password, lookup) from TP-Link's SPA.

    For each position h up to max(len(key), len(password)):
        u = ord(key[h])      or 187 if h >= len(key)
        d = ord(password[h]) or 187 if h >= len(password)
        result[h] = lookup[(u ^ d) % len(lookup)]
    """
    n, a, s = len(key), len(password), len(lookup)
    result = []
    for h in range(max(n, a)):
        u = d = 187
        if n <= h:
            d = ord(password[h])
        elif a <= h:
            u = ord(key[h])
        else:
            u = ord(key[h])
            d = ord(password[h])
        result.append(lookup[(u ^ d) % s])
    return "".join(result)


def js_encode(s: str) -> str:
    """Matches JavaScript encodeURIComponent — keeps A-Za-z0-9-_.!~*'()"""
    safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
    out = []
    for c in s:
        if c in safe:
            out.append(c)
        else:
            for byte in c.encode("utf-8"):
                out.append(f"%{byte:02X}")
    return "".join(out)


# ── Login ─────────────────────────────────────────────────────────────────────

def parse_challenge(body: str):
    """
    Parse the 401 challenge body.
    Format (CRLF lines):
        00007        <- type
        000NN        <- attempt counter
        000CC        <- sub-count
        <n_str>      <- XOR key (variable length)
        <lookup>     <- lookup table (variable length)
        00000        <- end marker
    Returns (n_str, lookup_table).
    """
    lines = [l.strip() for l in body.replace("\r\n", "\n").split("\n")
             if l.strip() and l.strip() != "00000"]
    # lines[0]=code, lines[1]=counter, lines[2]=sub-count, lines[3]=n_str, lines[4]=lookup
    if len(lines) >= 5:
        return lines[3], lines[4]
    return None, None


def login(http: PersistentHTTP, password: str) -> str:
    """
    Perform TDDP login on a persistent connection.
    Returns the session token (used as ?id= in subsequent requests).

    Flow (must be on same TCP connection):
      1. POST /?code=7&asyn=0&id=! → 401 with challenge (n_str + lookup_table)
      2. POST /?code=7&asyn=0&id=<encrypted> → 200 with session token
    """
    # Step 1 — get challenge
    status, body = http.post("/?code=7&asyn=0&id=!", body="")
    if status == 200:
        # Already logged in somehow; try to extract token
        lines = [l.strip() for l in body.replace("\r\n", "\n").split("\n") if l.strip()]
        return lines[1] if len(lines) > 1 else ""

    n_str, lookup = parse_challenge(body)
    if not n_str or not lookup:
        raise RuntimeError(f"Could not parse challenge from: {body!r}")

    # Step 2 — encrypt and login
    encrypted_id = su_encrypt(n_str, password, lookup)
    id_encoded = js_encode(encrypted_id)
    status, body = http.post(f"/?code=7&asyn=0&id={id_encoded}", body="")

    if status == 200:
        lines = [l.strip() for l in body.replace("\r\n", "\n").split("\n") if l.strip()]
        # Successful login body: "00000\r\n<session_token>"
        token = lines[1] if len(lines) > 1 else encrypted_id
        return token if token else encrypted_id
    else:
        raise RuntimeError(f"Login failed (HTTP {status}):\n{body}")


# ── Authenticated API ─────────────────────────────────────────────────────────

class RouterSession:
    def __init__(self, mac: str = ROUTER_MAC, port: int = PORT):
        self._mac = mac
        self._port = port
        self._host = None
        self._http = None
        self._session = None

    def _resolve(self):
        self._host = find_host(self._mac, last_ip=ROUTER_LAST_IP)
        self._http = PersistentHTTP(self._host, self._port)

    def connect(self, password: str):
        if self._http is None:
            self._resolve()
        print(f"Connecting to {self._host}...")
        self._session = login(self._http, password)

    def _url(self, code: int) -> str:
        return f"/?code={code}&asyn=0&id={js_encode(self._session)}"

    def query(self, code: int, body="") -> str:
        status, resp = self._http.post(self._url(code), body=body)
        if status not in (200, 401):
            raise RuntimeError(f"HTTP {status}: {resp[:200]}")
        return resp

    def reboot(self, wait: bool = True):
        """Send reboot command (code=6). If wait=True, blocks until router is back."""
        self._http.post(self._url(6), body="")
        self._http.close()
        if wait:
            print("Rebooting", end="", flush=True)
            time.sleep(8)  # give it time to actually go down
            deadline = time.time() + 120
            back = False
            while time.time() < deadline:
                try:
                    ip = _find_by_mac(self._mac, timeout=5)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((ip, self._port))
                    s.close()
                    back = True
                    break
                except Exception:
                    print(".", end="", flush=True)
                    time.sleep(3)
            if not back:
                raise RuntimeError("Router did not come back within 120s")
            print(" done")

    def close(self):
        if self._http:
            self._http.close()

    # ── High-level helpers ────────────────────────────────────────────────────

    def device_mac(self) -> str:
        resp = self.query(8)
        lines = [l.strip() for l in resp.replace("\r\n", "\n").split("\n") if l.strip()]
        return lines[1] if len(lines) > 1 else resp.strip()

    def network_map(self) -> list:
        """Returns list of IP addresses of connected devices."""
        resp = self.query(2, body="13|1,0,0")
        ips = []
        for line in resp.replace("\r\n", "\n").split("\n"):
            line = line.strip()
            if line.startswith("ip "):
                parts = line.split()
                if len(parts) >= 3 and parts[2] != "0.0.0.0":
                    ips.append(parts[2])
        return ips

    def plc_block(self) -> dict:
        """Read powerline block 121 — returns dict with mac, networkName, powerlineKey."""
        resp = self.query(2, body="121|1,0,0")
        result = {}
        for line in resp.replace("\r\n", "\n").split("\n"):
            line = line.strip()
            if " " in line and not line.startswith("id ") and not line.startswith("00"):
                key, _, val = line.partition(" ")
                result[key] = val.strip()
        return result

    def plc_neighbors(self, plc_mac: str) -> list:
        """
        Query powerline neighbor stations using the LOCAL PLC mac address.
        Returns list of (neighbor_mac, tx_mbps, rx_mbps) tuples.
        """
        resp = self.query(0, body=f"main plc getNwInfo -m {plc_mac.upper()}")
        neighbors = []
        for line in resp.replace("\r\n", "\n").split("\n"):
            parts = line.strip().split()
            if len(parts) == 3 and "-" in parts[0] and parts[1].isdigit():
                neighbors.append((parts[0], int(parts[1]), int(parts[2])))
        return neighbors


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "--password-file":
        with open(sys.argv[2]) as f:
            content = f.read().strip()
        # Accept plain password or shell assignment (KEY=value / export KEY=value)
        if "=" in content:
            content = content.split("=", 1)[1].strip().strip("'\"")
        password = content
        cmd = sys.argv[3] if len(sys.argv) > 3 else "info"
        args = sys.argv[4:]
    elif "TPLINK_PASSWORD" in os.environ:
        password = os.environ["TPLINK_PASSWORD"]
        cmd = sys.argv[1] if len(sys.argv) > 1 else "info"
        args = sys.argv[2:]
    elif len(sys.argv) > 1:
        password = sys.argv[1]
        cmd = sys.argv[2] if len(sys.argv) > 2 else "info"
        args = sys.argv[3:]
    else:
        print("Error: password required — pass as argument, --password-file <path>, or set TPLINK_PASSWORD env var")
        sys.exit(1)

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]")
    router = RouterSession()
    try:
        router.connect(password)

        if cmd == "info":
            mac = router.device_mac()
            print(f"\nDevice MAC (Ethernet) : {mac}")

            plc = router.plc_block()
            plc_mac = plc.get("mac", "")
            print(f"\nPowerline adapter:")
            print(f"  Local PLC MAC  : {plc_mac}")
            print(f"  Network name   : {plc.get('networkName', '?')}")
            print(f"  Powerline key  : {plc.get('powerlineKey', '?')}")
            if plc_mac:
                neighbors = router.plc_neighbors(plc_mac)
                for nb_mac, tx, rx in neighbors:
                    print(f"  Neighbor {nb_mac} : TX={tx} Mbps, RX={rx} Mbps")

            print(f"\nConnected devices:")
            ips = router.network_map()
            for ip in ips:
                print(f"  {ip}")

        elif cmd == "devices":
            ips = router.network_map()
            print("Connected device IPs:")
            for ip in ips:
                print(f"  {ip}")

        elif cmd == "plc":
            plc = router.plc_block()
            plc_mac = plc.get("mac", "")
            print(f"Local PLC MAC : {plc_mac}")
            print(f"Network name  : {plc.get('networkName', '?')}")
            print(f"Powerline key : {plc.get('powerlineKey', '?')}")
            if plc_mac:
                neighbors = router.plc_neighbors(plc_mac)
                for nb_mac, tx, rx in neighbors:
                    print(f"Neighbor {nb_mac} : TX={tx} Mbps, RX={rx} Mbps")

        elif cmd == "reboot":
            router.reboot(wait=True)

        elif cmd == "raw":
            if not args:
                print("Usage: raw <code> [body]")
                sys.exit(1)
            code = int(args[0])
            body = args[1] if len(args) > 1 else ""
            print(router.query(code, body=body))

        else:
            print(f"Unknown command: {cmd}")
            print(__doc__)
            sys.exit(1)

    finally:
        router.close()


if __name__ == "__main__":
    main()
