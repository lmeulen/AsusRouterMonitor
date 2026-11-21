# Security policy

## Supported versions

Security fixes target current `development` branch and latest released major version.

## Reporting a vulnerability

Do not file public issue for suspected vulnerability or include router credentials, tokens, router configuration, public IP addresses, MAC addresses, SSIDs, or raw router responses. Contact repository owner privately through GitHub instead.

## Deployment boundary

This project supports routers reachable from a trusted LAN or VPN. Direct router administration exposure to WAN is out of scope. HTTPS certificate verification is enabled by default; use `--insecure` only for a trusted LAN router with a self-signed certificate.
