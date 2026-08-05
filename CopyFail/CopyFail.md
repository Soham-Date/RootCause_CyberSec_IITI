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





### Visual Evidence

- **Screenshot/GIF:** Before and after file state
- **Terminal output:** PoC execution and success indicators
- **Kernel logs:** Any relevant dmesg output during exploitation

[Screenshots/GIFs to be added during testing]

---

## Technical Breakdown

### The Race Condition Window

```
Timeline of vulnerable execution:

[Process A]                          [Process B - Attacker]
-----------                          ----------------------
Read page state
                                     Initiate copy operation
                                     Begin racing condition
Check permissions
                                     Modify page metadata
Copy page (with stale perms)
Write result
                                     Access sensitive data
```

### Why Normal Locking Fails

[Insert explanation of why existing lock mechanisms don't prevent this race]

---

## Patch & Mitigation

### Kernel Patch

**Commit:** [upstream commit hash]  
**Author:** [developer name]  
**Date:** [patch date]

**Key changes:**
1. Add atomic operations to [specific code section]
2. Increase synchronization granularity
3. Validate page state before copy completion

### Example Patch

```c
// BEFORE (vulnerable)
void copy_page_vulnerable(struct page *src, struct page *dst) {
    void *src_addr = kmap_atomic(src);
    void *dst_addr = kmap_atomic(dst);
    memcpy(dst_addr, src_addr, PAGE_SIZE);
    kunmap_atomic(dst_addr);
    kunmap_atomic(src_addr);
}

// AFTER (patched)
void copy_page_fixed(struct page *src, struct page *dst) {
    spin_lock(&page_lock);
    validate_page_state(src, dst);
    
    void *src_addr = kmap_atomic(src);
    void *dst_addr = kmap_atomic(dst);
    memcpy(dst_addr, src_addr, PAGE_SIZE);
    kunmap_atomic(dst_addr);
    kunmap_atomic(src_addr);
    
    spin_unlock(&page_lock);
}
```

### Backports

- **Linux 5.15 LTS:** Available in [commit/tag]
- **Linux 5.4 LTS:** Available in [commit/tag]
- **Ubuntu 22.04 LTS:** Included in kernel [version]

### Workarounds

Until patching is possible:
- Run only trusted code
- Restrict use of [vulnerable syscall/feature]
- Monitor kernel logs for suspicious activity

---

## Impact Assessment

### Security Implications

- **Confidentiality:** Sensitive kernel memory could be leaked
- **Integrity:** Kernel structures and file contents could be corrupted
- **Availability:** System crash or denial of service possible

### Real-World Scenarios

- Privilege escalation to root
- Bypass of security module restrictions (SELinux, AppArmor)
- Theft of cryptographic keys from kernel memory

---

## References

- [NVD CVE Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- Upstream Linux kernel commit: [link]
- LWN.net coverage: [link if available]
- Ubuntu Security Notices: [link]

---

## Notes & Learnings

- [Add learnings from reproduction process]
- [Challenges encountered during PoC development]
- [Differences from similar vulnerabilities (Dirty COW, DirtyPipe, etc.)]

---

*Last Updated: [Date]*  
*Status: [Proof of Concept Pending / In Progress / Complete]*
