# Custom Network Proxy Server (HTTP + HTTPS CONNECT)

A multithreaded **forward proxy server** implemented in **Python** using low-level **TCP socket programming**.

## Features
- **HTTP proxying** (GET/POST with `Content-Length`)
- **Domain blocking** via `config/blocked.txt`
- **Request logging** to `logs/proxy.log` (ALLOW/BLOCKED/ERROR + bytes)
- **HTTPS via CONNECT tunneling** (bidirectional TCP tunnel)
- **Concurrency**: thread-per-connection (handles multiple clients simultaneously)

## Folder Structure
```
proxy-project/
  src/
    proxy.py
  config/
    blocked.txt
  logs/
    proxy.log
  tests/
  docs/
```

## How to Run (Windows)
```bash
cd D:\repo\proxy-project
python src\proxy.py
```

Default listen address: `127.0.0.1:8888`.

## Configuration: Blocklist
Edit `config/blocked.txt` (one domain per line, `#` for comments):
```
example.com
google.com
# comments are allowed
```

Rules:
- Exact domain match blocks the domain
- Parent-domain match blocks subdomains too (e.g., `example.com` blocks `www.example.com`)

## Logging
Logs are written to `logs/proxy.log`.

### HTTP (normal requests)
```
YYYY-MM-DD HH:MM:SS UTC | ALLOW   | <client_ip>:<client_port> -> GET example.com:80/ | bytes=822
YYYY-MM-DD HH:MM:SS UTC | BLOCKED | <client_ip>:<client_port> -> GET example.com:80/
```

### HTTPS CONNECT
```
YYYY-MM-DD HH:MM:SS UTC | ALLOW   | <client_ip>:<client_port> -> CONNECT example.com:443 | c2s=659 s2c=5699
YYYY-MM-DD HH:MM:SS UTC | BLOCKED | <client_ip>:<client_port> -> CONNECT example.com:443
```

## Testing (Commands)

### 1) HTTP Allow
(Remove `example.com` from blocklist)
```bash
curl -v http://example.com -x http://127.0.0.1:8888
```

### 2) HTTP Block
(Add `example.com` to `config/blocked.txt`, restart proxy)
```bash
curl -v http://example.com -x http://127.0.0.1:8888
```

### 3) HTTPS Allow (CONNECT)
(Remove `example.com` from blocklist, restart proxy)
```bash
curl -v https://example.com -x http://127.0.0.1:8888
```

### 4) HTTPS Block (CONNECT blocked)
(Add `example.com` to blocklist, restart proxy)
```bash
curl -v https://example.com -x http://127.0.0.1:8888
```

## Limitations / Future Improvements
- No HTTP response caching (optional improvement)
- Request-body handling assumes `Content-Length` (chunked request bodies not fully supported)
- No authentication
- No HTTP/2 or QUIC support (HTTP/1.1 over TCP)

## License
For academic use.
