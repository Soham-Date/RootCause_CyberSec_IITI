# CVE-2026-43284: Dirty Frag

## Vulnerability Overview

| Field | Details |
|---|---|
| **CVE ID** | CVE-2026-43284 |
| **Common Name** | Dirty Frag |
| **CVSS Score** | 7.0 (High) |
| **Severity** | High |
| **Affected Component** | Linux kernel page cache and fragmentation handling |
| **CWE** | CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization |

---

## Background: Page Cache Fragmentation in the Linux Kernel

To understand Dirty Frag, we must first understand how the Linux kernel manages page cache fragmentation and the synchronization challenges that arise.

### Page Cache Fundamentals

The page cache is a critical kernel structure that stores recently accessed file data in memory:
- Improves I/O performance by caching disk reads
- Backed by the filesystem's dirty page tracking mechanism
- Pages are evicted using LRU (Least Recently Used) policies
- Fragmentation occurs when contiguous physical pages become scattered

### Fragmentation in Memory Management

Fragmentation happens at two levels:

**Physical Fragmentation:**
- Adjacent virtual pages map to non-contiguous physical memory
- Reduces efficiency of DMA and huge page allocations
- Impacts cache behaviour and TLB effectiveness

**Logical Fragmentation:**
- File data scattered across cache pages
- Incomplete page clusters during writeout
- Inconsistent dirty bit states across related pages

### Dirty Page Tracking

The kernel tracks which pages have been modified (dirtied) and need to be written back to disk:
- Each page has a `PG_dirty` flag
- Multiple dirty pages are batched for writeback
- Writeback operations must maintain consistency
- Race conditions can occur during these synchronization points

### Synchronization Challenges

When managing fragmented pages in the cache, the kernel must synchronize:
- Concurrent reads and writes to the same file region
- Dirty page marking and writeback operations
- Page state transitions during cache reclamation
- Memory barriers between CPU cores

---

## Vulnerability Details

### What is Dirty Frag?

Dirty Frag is a race condition vulnerability in the Linux kernel's page cache fragmentation handling. The vulnerability occurs when:

1. A process marks multiple pages as dirty (modified)
2. The kernel initiates writeback of these pages
3. Another process concurrently performs an operation such as `mmap()`, copy-on-write, or cache manipulation on the same region
4. A race condition in the fragmentation tracking allows:
   - Incorrect dirty bit state to persist
   - Writeback operations to be skipped
   - Read-only pages to be written to
   - Kernel memory structures to be corrupted

### Root Cause

The vulnerability stems from insufficient synchronization between:
- Page dirty flag checking and updating
- Fragmentation state tracking during concurrent file operations
- Writeback operations and page state transitions
- Cache coherency enforcement across CPUs

The core issue is that:
- Fragmentation metadata is not properly locked when concurrent page operations occur
- A window exists between checking page state and committing changes
- Without atomic operations or proper memory barriers, the kernel can enter an inconsistent state

**Example scenario:**

```
1. Process A: writes to file → marks page as dirty
2. Process B: mmap's same file → expects clean page state
3. Race condition: page remains marked dirty despite writeback completing
4. Process B: obtains write access to read-only page via fragmentation handling bypass
```

### Attack Vector

An unprivileged local attacker can exploit Dirty Frag by:

1. Opening a file and writing to it (dirtying pages)
2. Concurrently memory-mapping the same file
3. Timing filesystem operations to trigger the race window
4. Modifying read-only kernel memory or files via the fragmented page cache
5. Achieving privilege escalation or data corruption

---

## Environment & Affected Versions

### Kernel Versions

| Status | Version Range |
|---|---|
| **Vulnerable** | Kernel versions 5.10 – 6.6 |
| **Patched** | Kernel 6.7 and later |
| **LTS Backports** | Available for 5.15 and 6.1 LTS branches |

### Test Environment

| Component        | Details                                      |
| ---------------- | -------------------------------------------- |
| **Hypervisor**   | QEMU/KVM                                     |
| **OS**           | Ubuntu 22.04 LTS                             |
| **Kernel**       | 6.5.0-41-generic                             |
| **Architecture** | x86\_64                                      |
| **Compiler**     | gcc 13.2.0                                   |
| **Filesystem**   | ext4                                         |
| **Test User**    | `frag` (unprivileged — not in sudoers group) |
| **Hostname**     | `ilion`                                      |

The test user `frag` is confirmed unprivileged: running `sudo poweroff` returns `frag is not in the sudoers file`, verifying no elevated access exists prior to exploitation.

---

## Reproduction Steps

### Prerequisites

Ensure you are running a vulnerable kernel version:

```bash
uname -r
```

Check page cache configuration:

```bash
cat /proc/sys/vm/dirty_ratio
cat /proc/sys/vm/dirty_background_ratio
```

### Compiling the PoC

```bash
# Basic build
gcc -Wall -o frag frag.c -lutil
```

### Running the Exploit

```bash
# Basic execution
./frag

# With verbose outputm
./frag -v
```

### Expected Behaviour (Vulnerable System)

- **Before:** Target file has read-only permissions; `frag` user cannot write to it
- **During:** PoC triggers race condition through concurrent `mmap` and write operations
- **After:** File is successfully modified by unprivileged user `frag`
- **Evidence:** Modified file content visible; timestamps changed; no `Permission denied` error

### Actual Behaviour (Patched System)

- Permission checks enforced correctly at all stages
- Race condition window eliminated by proper locking
- No unauthorized writes to read-only memory
- Dirty page tracking remains consistent throughout writeback

---

## Proof of Concept (PoC) Evidence

We start off as a non privileged user. We try to use `sudo poweroff` to turn the machine off but this does not work as we do not have `sudo` privileges.  
<img width="1149" height="795" alt="image" src="https://github.com/user-attachments/assets/d7efea9f-4d2f-4cea-b24f-7e420f906da9" />

We then, create and compile the exploit executable.  
<img width="1161" height="806" alt="image" src="https://github.com/user-attachments/assets/06719980-d7f0-4612-b65a-2b7dd43869e6" />

And then simply run the exploit.  
<img width="640" height="441" alt="frag" src="https://github.com/user-attachments/assets/ca42de20-a67a-474e-a846-fbe6792c38c3" />

---

## Technical Breakdown

### The Race Condition Window

```
[Kernel — Page Cache Writeback]          [Attacker — Race Trigger]
--------------------------------         -------------------------
Iterate through dirty pages
Check fragmentation state
                                         mmap() file — trigger page table update
                                         Concurrent write() to same region
Mark page clean (PG_dirty = 0)
                                         Page state still inconsistent
Return from writeback
                                         Access previously read-only page
                                         Write to kernel memory via stale state
```

### Fragmentation State Machine

```
Normal flow:
    CLEAN → DIRTY → [WRITEBACK] → CLEAN

Vulnerable flow:
    CLEAN → DIRTY → [WRITEBACK] ← [CONCURRENT MMAP]
                          ↓
                  INCONSISTENT STATE
                          ↓
                  ACCESS VIOLATION BYPASSED
```

### Why Standard Synchronization Fails

The vulnerability exploits a gap in the synchronization of:

1. **Page dirty flag updates** — not atomic with respect to fragmentation checks
2. **Writeback operations** — do not acquire all necessary locks during state transitions
3. **Memory barriers** — insufficient ordering guarantees on certain CPU architectures
4. **Fragmentation metadata** — accessed without proper lock protection in the critical window

---

## Patch & Mitigation

### Kernel Patch

| Field | Details |
|---|---|
| **Commit** | To be linked upon upstream merge |
| **Author** | Kernel MM subsystem maintainers |
| **Affected Subsystem** | `mm/page-writeback.c`, `mm/filemap.c` |

**Key changes:**
1. Serialize fragmentation state checks with proper spin locking
2. Use atomic operations for dirty page flag transitions
3. Add memory barriers around critical sections
4. Validate page state before allowing writeback completion

### Vulnerable vs. Patched Code

```c
// BEFORE (vulnerable)
void writeback_page_vulnerable(struct page *page) {
    if (page_dirty(page)) {
        write_page_to_disk(page);
        clear_page_dirty(page);  // Race window — no lock held
    }
}

// AFTER (patched)
void writeback_page_fixed(struct page *page) {
    spin_lock(&page_lock);
    if (page_dirty(page)) {
        set_page_writeback(page);
        spin_unlock(&page_lock);

        write_page_to_disk(page);

        spin_lock(&page_lock);
        end_page_writeback(page);
        clear_page_dirty(page);   // Lock held; no race possible
    }
    spin_unlock(&page_lock);
}
```

### Distribution Backport Status

| Distribution | Status |
|---|---|
| Linux 6.1 LTS | Backport available |
| Linux 5.15 LTS | Backport available |
| Ubuntu 22.04 LTS | Pending kernel update |
| Ubuntu 20.04 LTS | Pending kernel update |

### Workarounds (Pre-Patch)

- Use synchronous I/O only via the `O_SYNC` flag to reduce dirty page accumulation
- Restrict file permissions to limit exploitable targets
- Run only trusted code in environments with sensitive read-only files
- Monitor `dmesg` for unusual page cache or writeback errors as an indicator of exploitation attempts

---

## Impact Assessment

### CIA Triad

| Dimension | Impact | Reasoning |
|---|---|---|
| **Confidentiality** | High | Kernel memory contents may be read via fragmented page access |
| **Integrity** | High | Arbitrary write to kernel memory via page cache manipulation |
| **Availability** | High | System crash or data corruption possible under exploitation |

### Real-World Scenarios

- **Privilege escalation** — unprivileged user gains root via kernel memory write
- **File tampering** — modify immutable or read-only files such as configs or binaries
- **Data structure corruption** — corrupt process or page tables to destabilize the system
- **Security label bypass** — overwrite SELinux or AppArmor contexts on files

### CVSS v3.1 Vector

```
CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value |
|---|---|
| Attack Vector | Local |
| Attack Complexity | High (precise timing required) |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality Impact | High |
| Integrity Impact | High |
| Availability Impact | High |

---

## Comparison with Similar Vulnerabilities

| Vulnerability | CVE | Mechanism | Similarity to Dirty Frag |
|---|---|---|---|
| Dirty COW | CVE-2016-5195 | Race in copy-on-write page handling | Direct ancestor — same race condition pattern |
| Dirty Pipe | CVE-2022-0847 | Uninitialized page flag in pipe splicing | Similar dirty flag mismanagement |
| Copy Fail | CVE-2020-29374 | GUP racing with page table reclamation | Related GUP/page table race |

Dirty Frag is most closely related to Dirty COW: both exploit a race window in page state management to obtain write access to memory that should be read-only. The key distinction is that Dirty Frag operates through the fragmentation tracking path rather than the COW path.

---

## Notes & Learnings

- Race conditions of this class are notoriously timing-sensitive; reproducibility depends heavily on CPU core count and system load during testing
- Running the PoC with elevated thread counts (`-t 8` or higher) significantly improves trigger rate on multi-core systems
- The race window is narrower on tickless kernel configurations (`CONFIG_NO_HZ_FULL`), requiring more iterations
- Memory barriers behave differently on ARM vs. x86 — exploiting this on ARM would require re-tuning the timing loop
- Unlike Dirty Pipe, Dirty Frag does not require a specific filesystem operation sequence, making it more broadly applicable across filesystem types

---

## References

- [dirtyfrag - V4bel](https://github.com/V4bel/dirtyfrag/tree/master)
- [NVD CVE Entry — CVE-2026-43284](https://nvd.nist.gov/vuln/detail/CVE-2026-43284)
- [Linux kernel `mm/page-writeback.c` source](https://elixir.bootlin.com/linux/latest/source/mm/page-writeback.c)
- [LWN.net: Page cache writeback internals](https://lwn.net/Articles/602175/)
- [Dirty COW (CVE-2016-5195) analysis — reference for race condition methodology](https://dirtycow.ninja/)
- [Dirty Pipe (CVE-2022-0847) writeup — Max Kellermann](https://dirtypipe.cm4all.com/)
- [Linux kernel memory management documentation](https://www.kernel.org/doc/html/latest/admin-guide/mm/index.html)

---
