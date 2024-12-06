# Mercury

Mercury is a light DNS server implementation from scratch in Go

## Capabilities

- Recursive resolver - resolves directly using the Internet root servers by default, eliminating the need to trust any external name servers.
- Authoritative server for your own zones.
- DNS sinkhole - (dns-level ad-block)
- Caches DNS queries
- Handles concurrent clients

[//]: # "## Why?"

## 🚀 Quick Start
### Install

#### Docker compose:

- `compose.yaml`
```yaml
services:
  mercury:
    image: ghcr.io/bernoussama/mercury:latest
    ports:
      - "${PORT}:53153/udp"
      - "${PORT}:53153/tcp"
    volumes:
      - ./zones:/opt/mercury/zones
```

- run the container in the background
```bash
PORT=53 docker compose up -d
```

### systemd service

> WIP


## ⚙️ Usage
> ⚠️ still in development

if you want to use just send dns requests to the server

example:
```bash
dig google.com @server-ip -p 53
```
 
> cli comming soon

## 👏 Contributing

Comments and pull requests are welcome and encouraged.

You can contribute by forking the repo and opening pull requests.
