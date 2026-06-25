<img width="1600" height="1214" alt="WhatsApp Image 2026-06-26 at 12 24 24 AM" src="https://github.com/user-attachments/assets/e1a5a3d2-1b5c-46e7-b858-2d66d17a665a" />
# PwnKit (CVE-2021-4034)

## Overview

PwnKit (CVE-2021-4034) is a local privilege escalation vulnerability affecting the Polkit `pkexec` utility on most Linux distributions. It was corrected by Qualys in January 2022. A local unprivileged user can exploit the flaw to execute arbitrary code with root privileges.

The vulnerability exists because `pkexec` incorrectly handles command-line arguments when executed without any arguments.

---

## Vulnerability Details

- **CVE:** CVE-2021-4034
- **Severity:** Critical (CVSS 7.8)
- **Affected Component:** `pkexec`
- **Affected Package:** Polkit
- **Access Required:** Local shell access
- **Impact:** Privilege Escalation (User → Root)

Since `pkexec` is installed by default on many Linux distributions and is marked as a SUID binary, the vulnerability became widespread across desktop and server environments.

---

## Root Cause

The vulnerability is caused by improper validation of command-line arguments inside `pkexec`.

When `pkexec` is executed with `argc = 0`, it incorrectly accesses memory outside the expected argument array. This out-of-bounds access allows an attacker to manipulate environment variables that should normally be sanitized.

By carefully controlling these environment variables, an attacker can force `pkexec` to load arbitrary shared libraries, eventually leading to execution of attacker-controlled code with root privileges.

---

## Exploitation

The exploit requires only a local user account.

A typical attack flow is:

1. Log in as an unprivileged user.
2. Execute a crafted PwnKit exploit.
3. Trigger the vulnerable `pkexec` binary.
4. Inject a malicious environment variable.
5. Gain a root shell.

No user interaction is required once the exploit is executed.

---

## Proof of concept exploit 

<img width="1600" height="1214" alt="WhatsApp Image 2026-06-26 at 12 24 24 AM" src="https://github.com/user-attachments/assets/b82d3149-ac88-4b4c-87b6-a26d97c001b6" />

## Impact

Successful exploitation allows an attacker to:

- Obtain root privileges.
- Execute arbitrary commands as root.
- Read or modify sensitive system files.
- Install malware or persistence mechanisms.
- Completely compromise the affected machine.

Because the vulnerability grants full administrative access, it is considered a high-impact local privilege escalation vulnerability.

---

## Mitigation

The recommended mitigation is to update Polkit to a patched version provided by the Linux distribution.

Temporary workarounds include:

- Removing the SUID permission from `pkexec`.
- Restricting local user access.
- Monitoring systems for unusual privilege escalation attempts.

Applying official security updates is the preferred solution.

---

## References

- Qualys Security Advisory
- CVE-2021-4034
- Polkit Project Documentation
- MITRE CVE Database
