import socket
import threading
from urllib.parse import urlsplit
from datetime import datetime
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8888

BASE_DIR = Path(__file__).resolve().parent.parent
BLOCKLIST_FILE = BASE_DIR / "config" / "blocked.txt"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "proxy.log"


# -------------------------
# Logging + blocklist
# -------------------------
def log_line(msg: str):
    LOG_DIR.mkdir(exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def load_blocklist():
    if not BLOCKLIST_FILE.exists():
        return set()
    items = set()
    for line in BLOCKLIST_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            items.add(line)
    return items


def is_blocked(host: str, blockset: set) -> bool:
    h = host.strip().lower()
    if h in blockset:
        return True
    # block parent domains too: example.com blocks www.example.com
    parts = h.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in blockset:
            return True
    return False


# -------------------------
# Receive helpers
# -------------------------
def recv_until_headers_end(conn, max_bytes=65536):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > max_bytes:
            raise ValueError("Header too large")
    return data


def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(min(4096, n - len(data)))
        if not chunk:
            break
        data += chunk
    return data


# -------------------------
# HTTP parsing счита
# -------------------------
def parse_http_request(raw: bytes):
    """
    Parses HTTP request headers.
    Returns:
      method, target, http_version, headers_dict, body_part
    """
    if b"\r\n\r\n" in raw:
        head_bytes, body_part = raw.split(b"\r\n\r\n", 1)
    else:
        head_bytes, body_part = raw, b""

    text = head_bytes.decode(errors="replace")
    lines = text.split("\r\n")

    request_line = lines[0]
    parts = request_line.split()
    if len(parts) != 3:
        raise ValueError(f"Bad request line: {request_line}")

    method, target, http_version = parts

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return method, target, http_version, headers, body_part


def resolve_host_port_path(method, target, headers):
    """
    Returns host, port, path for normal HTTP methods (GET/POST/...)
    Handles absolute-URI and relative-path.
    """
    host = None
    port = 80
    path = "/"

    if target.startswith("http://") or target.startswith("https://"):
        u = urlsplit(target)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
    else:
        path = target
        host_header = headers.get("host")
        if host_header:
            if ":" in host_header:
                host, p = host_header.split(":", 1)
                port = int(p)
            else:
                host = host_header

    if not host:
        raise ValueError("No Host found")

    return host, port, path


# -------------------------
# Responses
# -------------------------
def send_403(conn):
    body = b"403 Forbidden (Blocked by proxy)\n"
    resp = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Connection: close\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    conn.sendall(resp)


def send_502(conn):
    body = b"502 Bad Gateway\n"
    resp = (
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Connection: close\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    conn.sendall(resp)


# -------------------------
# Forwarding helpers
# -------------------------
def build_forward_request(method, path, http_version, headers, host):
    headers.pop("proxy-connection", None)
    if "host" not in headers:
        headers["host"] = host
    headers["connection"] = "close"

    header_lines = []
    for k, v in headers.items():
        header_lines.append(f"{k.title()}: {v}")

    req = f"{method} {path} {http_version}\r\n" + "\r\n".join(header_lines) + "\r\n\r\n"
    return req.encode()


def relay_oneway(src, dst):
    """
    Relay bytes from src to dst until src closes.
    Returns total bytes relayed.
    """
    total = 0
    while True:
        data = src.recv(4096)
        if not data:
            break
        dst.sendall(data)
        total += len(data)
    return total


def tunnel_bidirectional(client_sock, server_sock):
    """
    Bidirectional tunnel for CONNECT: client<->server.
    Returns (bytes_client_to_server, bytes_server_to_client)
    """
    counts = {"c2s": 0, "s2c": 0}

    def c2s():
        try:
            counts["c2s"] = relay_oneway(client_sock, server_sock)
        except:  # noqa
            pass
        finally:
            try:
                server_sock.shutdown(socket.SHUT_WR)
            except:
                pass

    def s2c():
        try:
            counts["s2c"] = relay_oneway(server_sock, client_sock)
        except:  # noqa
            pass
        finally:
            try:
                client_sock.shutdown(socket.SHUT_WR)
            except:
                pass

    t1 = threading.Thread(target=c2s, daemon=True)
    t2 = threading.Thread(target=s2c, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    return counts["c2s"], counts["s2c"]


# -------------------------
# CONNECT parsing
# -------------------------
def parse_connect_target(target: str):
    """
    CONNECT target is like: "example.com:443"
    Returns host, port
    """
    if ":" not in target:
        raise ValueError("Bad CONNECT target (expected host:port)")
    host, p = target.split(":", 1)
    return host.strip(), int(p.strip())


# -------------------------
# Client handler
# -------------------------
def handle_client(conn, addr):
    server_sock = None
    start = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    client_ip, client_port = addr[0], addr[1]

    try:
        blockset = load_blocklist()

        raw = recv_until_headers_end(conn)
        method, target, http_version, headers, body_part = parse_http_request(raw)
        method_upper = method.upper()

        # -------------------------
        # HTTPS via CONNECT (tunnel)
        # -------------------------
        if method_upper == "CONNECT":
            dst_host, dst_port = parse_connect_target(target)

            # blocklist check (by hostname)
            if is_blocked(dst_host, blockset):
                send_403(conn)
                msg = f"{start} | BLOCKED | {client_ip}:{client_port} -> CONNECT {dst_host}:{dst_port}"
                log_line(msg)
                print("[!] " + msg)
                return

            print(f"[+] {client_ip}:{client_port} -> CONNECT {dst_host}:{dst_port}")

            # connect to target host:port
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((dst_host, dst_port))

            # reply to client: tunnel established
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # now tunnel raw bytes both ways (TLS will flow here)
            c2s_bytes, s2c_bytes = tunnel_bidirectional(conn, server_sock)

            msg = (
                f"{start} | ALLOW   | {client_ip}:{client_port} -> CONNECT {dst_host}:{dst_port}"
                f" | c2s={c2s_bytes} s2c={s2c_bytes}"
            )
            log_line(msg)
            print("[*] " + msg)
            return

        # -------------------------
        # Normal HTTP forwarding
        # -------------------------
        host, port, path = resolve_host_port_path(method_upper, target, headers)

        # blocklist check
        if is_blocked(host, blockset):
            send_403(conn)
            msg = f"{start} | BLOCKED | {client_ip}:{client_port} -> {method_upper} {host}:{port}{path}"
            log_line(msg)
            print("[!] " + msg)
            return

        # read body if needed (Content-Length)
        content_length = int(headers.get("content-length", "0") or "0")
        if content_length > 0:
            remaining = content_length - len(body_part)
            if remaining > 0:
                body_part += recv_exact(conn, remaining)

        print(f"[+] {client_ip}:{client_port} -> {method_upper} {host}:{port}{path}")

        # connect to destination
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((host, port))

        # send rebuilt request
        forward_head = build_forward_request(method_upper, path, http_version, headers, host)
        server_sock.sendall(forward_head + body_part)

        # relay response back to client
        bytes_to_client = relay_oneway(server_sock, conn)

        msg = f"{start} | ALLOW   | {client_ip}:{client_port} -> {method_upper} {host}:{port}{path} | bytes={bytes_to_client}"
        log_line(msg)
        print("[*] " + msg)

    except Exception as e:
        print("[!] Error:", e)
        try:
            send_502(conn)
        except:
            pass
        log_line(f"{start} | ERROR   | {client_ip}:{client_port} -> {e}")

    finally:
        if server_sock:
            try:
                server_sock.close()
            except:
                pass
        try:
            conn.close()
        except:
            pass


# -------------------------
# Main loop
# -------------------------
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)
    print(f"[*] Proxy listening on {HOST}:{PORT}")
    print(f"[*] Blocklist: {BLOCKLIST_FILE}")
    print(f"[*] Log file : {LOG_FILE}")

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
