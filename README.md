# copilot-security-vulnerabilities
Hardened Node.js Express app originally built for security scanner testing.

## Setup
```bash
npm install
```

## Configuration
Set database credentials through environment variables:
```
DB_HOST=<hostname>
DB_USER=<username>
DB_PASSWORD=<password>
DB_NAME=<database>
```

## Run
```bash
npm start
```

## Security hardening highlights
- Parameterized SQL queries with hashed password verification using bcrypt
- Reflected XSS mitigated by escaping user-controlled output
- Cryptographically secure token generation
- Global rate limiting via `express-rate-limit`
- Restricted command execution to an allowlist
- Safe, normalized file reads restricted to `safe_files/`
