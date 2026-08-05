# CVE-2026-31431: Copy Fail

# Vulnerability Overview

CVE-2026-31431 is a local privilege escalation vulnerability in the Linux kernel's **AF_ALG (Crypto API)** subsystem. The vulnerability results from improper handling of scatter-gather (`scatterlist`) structures during cryptographic operations. Under specific conditions, an unprivileged local user can manipulate kernel memory mappings, allowing file-backed page cache pages to become writable. This enables modification of privileged executables through the page cache without directly writing to the filesystem, ultimately leading to privilege escalation.

---

# Vulnerability Details

The vulnerability exists in the interaction between the AF_ALG socket interface, the Linux Crypto API, scatter-gather (`scatterlist`) structures, and the page cache.

AF_ALG accepts user-provided source (`req->src`) and destination (`req->dst`) buffers for cryptographic operations. Due to incorrect handling of destination scatterlists, the kernel may reference page cache pages directly without enforcing normal write protections.

When the cryptographic request is processed, the kernel writes the output directly into these page cache pages. Since executable files are later loaded from the page cache, the modified contents are used during execution even though the underlying file remains protected by filesystem permissions.

---

# Root Cause

The root cause is improper validation and handling of destination scatterlist buffers inside the Linux Crypto API.

During AF_ALG request processing:

- User-controlled memory is converted into scatterlist entries.
- The kernel constructs source (`req->src`) and destination (`req->dst`) scatterlists.
- Scatterlist chaining (`sg_chain()`) may cause page cache pages to be referenced as writable destination buffers.
- The crypto subsystem performs write operations directly into these pages.
- The kernel fails to prevent writes to read-only, file-backed page cache pages.

As a result, protected executable data stored in the page cache can be modified without normal filesystem permission checks.

---

# Attack Vector

**Attack Complexity:** Low

**Privileges Required:** Local, unprivileged user

An attacker performs the following steps:

1. Create an AF_ALG socket.
2. Configure a cryptographic request.
3. Prepare controlled source and destination buffers.
4. Trigger the vulnerable cryptographic operation.
5. Cause the kernel to overwrite file-backed page cache pages.
6. Execute the modified privileged binary.
7. Obtain root privileges.

---

# Environment & Affected Versions

## Kernel Versions

**Vulnerable:** Linux kernel versions **4.14 - 6.19.11**

**Patched:** Linux kernel **6.19.12** and later

**Status:** Backports available for supported LTS branches

## Test Environment

| Component | Configuration |
|-----------|---------------|
| Hypervisor | QEMU/KVM |
| Operating System | Ubuntu *(replace with your version)* |
| Kernel | *(replace with the vulnerable kernel version used for testing)* |
| Architecture | x86_64 |
| Compiler | GCC *(replace with version)* |
| Build Tools | gcc, make, binutils, libc development packages |

---

# Reproduction Steps

1. Boot a system running a vulnerable Linux kernel (4.14–6.19.11).
2. Verify that the AF_ALG Crypto API is available.
3. Compile the proof-of-concept (PoC) exploit using GCC.
4. Execute the exploit as an unprivileged user.
5. The exploit creates an AF_ALG socket and prepares crafted cryptographic requests.
6. Carefully constructed scatterlists cause the crypto subsystem to treat file-backed page cache pages as writable destination buffers.
7. The kernel writes attacker-controlled data into the page cache during the cryptographic operation.
8. Execute the modified privileged binary.
9. Verify successful privilege escalation.

> **Note:** Perform testing only in an isolated virtual machine using a vulnerable kernel version. Do not execute the exploit on production systems.

## Proof of Concept (PoC) Evidence






<img width="1600" height="233" alt="WhatsApp Image 2026-08-02 at 5 25 29 PM" src="https://github.com/user-attachments/assets/c7fbb6c7-812a-45ea-9bfe-40d1e65314aa" />





<img width="723" height="362" alt="merged" src="https://github.com/user-attachments/assets/9c4915c5-57c4-4204-b137-6eaa4008fd9a" />


# Technical Breakdown

The vulnerability resides within the Linux kernel's **AF_ALG (Address Family Algorithm)** interface, which provides user-space access to the kernel Crypto API.

During an AF_ALG cryptographic request, the kernel creates two scatter-gather lists:

- **Source (`req->src`)**: References the input data.
- **Destination (`req->dst`)**: References the location where the cryptographic output will be written.

These scatterlists describe memory pages instead of requiring contiguous memory, allowing the crypto subsystem to efficiently process large buffers.

The vulnerability occurs because destination scatterlists are not sufficiently validated before being used by the crypto subsystem. Through carefully crafted AF_ALG requests, file-backed page cache pages can become writable destinations.

The crypto operation subsequently writes directly into these page cache pages. Although the filesystem itself remains unchanged, future executions of the affected executable use the modified page cache contents, resulting in unauthorized code execution.

The exploit relies entirely on legitimate kernel cryptographic operations and does not require bypassing filesystem permissions directly. Instead, it abuses incorrect memory handling inside the kernel.

---

# Patch and Mitigation

The vulnerability was fixed by strengthening validation of destination scatterlists within the Linux Crypto API.

The patch ensures that:

- File-backed page cache pages cannot be used as writable crypto destinations.
- Scatterlist entries are properly validated before write operations.
- Invalid memory mappings are rejected before the cryptographic request is processed.
- Kernel write protections are enforced throughout the AF_ALG request lifecycle.

## Mitigation

Systems can be protected by:

- Upgrading to **Linux kernel 6.19.12 or later**.
- Applying vendor-provided backports for supported LTS kernels.
- Restricting access to AF_ALG interfaces where practical.
- Keeping systems updated with the latest security patches.

---

# Impact Assessment

| Metric | Assessment |
|--------|------------|
| Vulnerability Type | Local Privilege Escalation |
| Attack Complexity | Low |
| Privileges Required | Local User |
| User Interaction | None |
| Scope | Local System |
| Impact | Root privilege escalation |
| Affected Component | Linux AF_ALG Crypto API |
| Exploitability | High on vulnerable kernels |

Successful exploitation allows an unprivileged local user to execute arbitrary code with root privileges by modifying privileged executables through the kernel page cache.

---

# References

- Linux Kernel Security Advisory for **CVE-2026-31431**
- Linux Kernel Git Repository (Patch Commit)
- Linux Kernel Crypto API Documentation
- Linux AF_ALG Documentation
- Common Vulnerabilities and Exposures (CVE) Database
- National Vulnerability Database (NVD)
- Relevant Linux distribution security advisories (Ubuntu, Debian, Fedora, Red Hat, SUSE)

---

# Notes and Learnings

During the analysis of CVE-2026-31431, several important Linux kernel concepts became essential for understanding the vulnerability:

- The AF_ALG socket interface allows user-space applications to access the Linux Crypto API.
- Scatter-gather (`scatterlist`) structures describe memory as a collection of pages rather than a single contiguous buffer.
- Source (`req->src`) and destination (`req->dst`) scatterlists determine where cryptographic operations read and write data.
- The Linux page cache stores cached file contents in RAM to improve filesystem performance.
- Writing to page cache pages differs from writing directly to files on disk.
- Improper validation of destination scatterlists can unintentionally expose protected page cache pages to kernel write operations.
- The vulnerability demonstrates how memory management mistakes can bypass traditional filesystem permission checks.
- Studying this vulnerability provides insight into Linux kernel memory management, scatterlists, page cache behavior, AF_ALG sockets, and secure validation of kernel data structures.

This project highlights the importance of validating kernel memory references before performing write operations, especially when user-controlled inputs interact with privileged kernel subsystems.


f Concept Pending / In Progress / Complete]*
