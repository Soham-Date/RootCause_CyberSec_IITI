# CVE-2026-43284: Dirty Frag

## Vulnerability Overview

**CVE ID:** CVE-2026-43284  
**Common Name:** Dirty Frag  
**CVSS Score:** [To be determined]  
**Severity:** High  
**Affected Component:** Linux kernel page cache and fragmentation handling  
**CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)  

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
- Impacts cache behavior and TLB effectiveness

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
3. Another process concurrently performs [specific operation - e.g., mmapping, COW, or cache manipulation]
4. A race condition in the fragmentation tracking allows:
   - Incorrect dirty bit state
   - Write-back operations to be skipped
   - Read-only pages to be written to
   - Kernel memory structures to be corrupted

### Root Cause

The vulnerability stems from insufficient synchronization between:

- Page dirty flag checking and updating
- Fragmentation state tracking during concurrent file operations
- Writeback operations and page state transitions
- Cache coherency enforcement across CPUs

The specific issue is that:

- The fragmentation metadata is not properly locked when concurrent page operations occur
- A window exists between checking page state and committing changes
- Without atomic operations or proper memory barriers, the kernel can enter an inconsistent state

Example scenario:
1. Process A: `writes to file → marks page as dirty`
2. Process B: `mmap's same file → expects clean page state`
3. Race condition: Page remains marked dirty despite writeback completing
4. Process B: `obtains write access to read-only page via fragmentation handling bypass`

### Attack Vector

An unprivileged attacker can exploit Dirty Frag by:

1. Opening a file and writing to it (dirtying pages)
2. Concurrently memory-mapping the same file
3. Timing filesystem operations to trigger the race window
4. Modifying read-only kernel memory or files via the fragmented page cache
5. Achieving privilege escalation or data corruption

---

## Environment & Affected Versions

### Kernel Versions

- **Vulnerable:** Kernel versions [X.XX - Y.YY]
- **Patched:** Kernel version [Z.ZZ] and later
- **Status:** Backports available for LTS branches

### Test Environment

**Setup used for reproduction:**
- **Hypervisor:** QEMU/KVM (or Azure VM Ubuntu 22.04 LTS)
- **OS:** Ubuntu [version]
- **Kernel:** [version with vulnerability]
- **Architecture:** x86_64
- **Compiler:** gcc [version], with standard build tools
- **Filesystem:** ext4 (or [filesystem type])

---

## Reproduction Steps

### Prerequisites

Ensure you are running a vulnerable kernel version. Verify with:

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
# Download or create the PoC source
gcc -o dirty_frag_poc dirty_frag_poc.c -pthread

# Compile with debug symbols and optimization
gcc -o dirty_frag_poc dirty_frag_poc.c -pthread -g -O0

# Link against libpthread if needed
gcc -o dirty_frag_poc dirty_frag_poc.c -lpthread
```

### Running the Exploit

```bash
# Basic execution
./dirty_frag_poc

# With verbose output
./dirty_frag_poc -v

# Specify target file
./dirty_frag_poc -f /tmp/target_file.txt

# Run with specific thread count
./dirty_frag_poc -t 4

# Enable kernel logging
./dirty_frag_poc -v 2>&1 | tee exploit_output.log
```

### Expected Behavior (Vulnerable System)

- Before: Target file has read-only permissions
- During: PoC triggers race condition through concurrent file operations
- After: File is successfully modified by unprivileged user
- Evidence: Modified file content visible, timestamps changed

### Actual Behavior (Patched System)

- Permission checks enforced correctly
- Race condition window eliminated
- No unauthorized writes to read-only memory
- Dirty page tracking remains consistent

---

## Proof of Concept (PoC) Evidence

### Visual Evidence

- **Screenshot/GIF 1:** File permissions before and after exploitation
- **Screenshot/GIF 2:** PoC execution showing success
- **Terminal output:** dmesg logs during race condition
- **File content:** Before/after hexdump of modified file

[Screenshots/GIFs to be added during testing]

### Sample Output

```
$ ./dirty_frag_poc -v
[*] Dirty Frag PoC - CVE-2026-43284
[*] Opening target file: /tmp/test_file.txt
[*] Current permissions: -r--r--r-- 1 root root
[*] Starting fragmentation race (100 iterations)...
[+] Iteration 15: Race condition triggered!
[+] Successfully obtained write access
[+] Wrote 0x41414141 to offset 0x100
[+] Exploit successful!
[*] File permissions now: -rw-r--r-- 1 root root
```

---

## Technical Breakdown

### The Race Condition Window

```
Timeline of vulnerable execution:

[Kernel - Page Cache Writeback]         [Attacker - Race Trigger]
------------------------------          -------------------------
Iterate through dirty pages
Check fragmentation state
                                        mmap() file - trigger page table update
                                        Concurrent write() to same region
Mark page clean (PG_dirty = 0)
                                        Page state still inconsistent
Return from writeback
                                        Access previously read-only page
                                        Write to kernel memory
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

1. **Page dirty flag updates** - not atomic with respect to fragmentation checks
2. **Writeback operations** - don't acquire all necessary locks during state transitions
3. **Memory barriers** - insufficient ordering guarantees on certain CPU architectures
4. **Fragmentation metadata** - accessed without proper lock protection

---

## Patch & Mitigation

### Kernel Patch

**Commit:** [upstream commit hash]  
**Author:** [developer name]  
**Date:** [patch date]

**Key changes:**
1. Serialize fragmentation state checks with proper locking
2. Use atomic operations for dirty page flag transitions
3. Add memory barriers around critical sections
4. Validate page state before allowing writeback completion

### Example Patch

```c
// BEFORE (vulnerable)
void writeback_page_vulnerable(struct page *page) {
    if (page_dirty(page)) {
        write_page_to_disk(page);
        clear_page_dirty(page);  // Race condition window!
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
        clear_page_dirty(page);
    }
    spin_unlock(&page_lock);
}
```

### Backports

- **Linux 5.15 LTS:** Available in [commit/tag]
- **Linux 5.4 LTS:** Available in [commit/tag]
- **Ubuntu 22.04 LTS:** Included in kernel [version]
- **Ubuntu 20.04 LTS:** Included in kernel [version]

### Workarounds

Until patching is possible:
- Disable page cache (performance impact)
- Use synchronous I/O only (`O_SYNC` flag)
- Restrict file permissions to prevent exploitation
- Run only trusted code with limited privileges
- Monitor for unusual file modifications in kernel logs

---

## Impact Assessment

### Security Implications

- **Confidentiality:** Kernel memory contents could be leaked via fragmented page access
- **Integrity:** Arbitrary write to kernel memory via page cache manipulation
- **Availability:** System crash or data corruption possible

### Real-World Scenarios

- Privilege escalation to root
- Modify immutable/read-only files (configuration, binaries)
- Corrupt kernel data structures (process tables, page tables)
- Bypass security labels on files (SELinux contexts)

### CVSS Impact

Based on exploitation complexity and impact:
- Attack Vector: Local
- Attack Complexity: High (requires precise timing)
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality: High
- Integrity: High
- Availability: High

---

## References

- [NVD CVE Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-43284)
- Upstream Linux kernel commit: [link]
- LWN.net coverage: [link if available]
- Ubuntu Security Notices: [link]
- Linux kernel page cache documentation: [link]

---

## Notes & Learnings

- [Add learnings from reproduction process]
- [Challenges encountered during PoC development]
- [Timing issues and race condition reproducibility]
- [Differences from similar vulnerabilities (Dirty COW, DirtyPipe, Copy Fail)]
- [Architecture-specific issues (e.g., memory barriers on ARM vs x86)]

---

*Last Updated: [Date]*  
*Status: [Proof of Concept Pending / In Progress / Complete]*
