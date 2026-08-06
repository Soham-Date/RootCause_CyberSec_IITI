# CVE-2022-0847: Dirty Pipe

## Vulnerability Overview

| Field | Details |
|---|---|
| **CVE ID** | CVE-2022-0847 |
| **Common Name** | Dirty Pipe |
| **CVSS Score** | 7.8 (High) |
| **Severity** | High |
| **Affected Component** | Linux kernel pipe buffer flag handling |
| **Affected Versions** | Kernel 5.8 – 5.16.10 / 5.15.24 / 5.10.101 |
| **Patched Versions** | 5.16.11 / 5.15.25 / 5.10.102 |
| **CWE** | CWE-909: Missing Initialization of Resource |

---

## Root Cause

### Pipes and Inter-Process Communication (IPC)

Linux processes are isolated from each other by design — one process cannot directly read or write another's memory.
To allow processes to communicate, the kernel provides Inter-Process Communication (IPC) mechanisms. The pipe is one such mechanism.

A pipe is unidirectional. A process writes into one end of it, and another process receives that data from the other end.
When you run a command like `ls | grep foo` in a shell, the kernel creates a pipe between the two processes.
The output of `ls` flows into the pipe, and `grep` reads from it.

> **Note:** Realistically one would use something like `grep -r "key" foo`, but `ls` has been used here for demonstration purposes.

From the perspective of the kernel, a pipe is a **ring buffer** — a circular array of fixed-size slots called **pipe buffers**.
Each pipe buffer points to a memory page and carries metadata describing how that page is to be used.

### Page Cache

When a file is read from disk, the kernel does not read it fresh every time. Instead, it loads the file's contents into a region of memory called the **page cache** — a kernel-managed pool of memory pages, each holding a portion of file data.
Subsequent reads of the same file are served directly from the page cache, avoiding repeated disk access.
The kernel controls who can modify these cached pages based on file permissions.

### Splice

Normally, feeding data into a pipe requires copying from a cache page into user space. This is wasteful.
So instead of copying, `splice()` simply creates a **reference** to the cache page containing the file data — a zero-copy operation.
Each pipe buffer entry tracks this reference with a set of flags that describe what kind of page it points to and what operations are permitted on it.

### The Vulnerability

CVE-2022-0847, known as **Dirty Pipe**, is a flaw in the Linux kernel's pipe buffer flag handling, present from kernel version 5.8 until it was patched in 5.16.11 / 5.15.25 / 5.10.102.

The vulnerability works as follows:

One of the pipe buffer flags, `PIPE_BUF_FLAG_CAN_MERGE`, signals to the kernel that incoming write data can be merged directly into an existing pipe buffer page, rather than allocating a new one.

When a pipe buffer slot is **recycled for reuse**, the kernel fails to clear this flag. The old `CAN_MERGE` flag from a previous operation remains set on the recycled buffer.

An attacker then uses `splice()` to pull data from a read-only file into the pipe. Because `splice()` does not create a copy, the pipe buffer now references the **actual page cache page** of that file.

The attacker then writes into the pipe. The kernel sees `PIPE_BUF_FLAG_CAN_MERGE` is set and, instead of allocating a fresh page, merges the write directly into the referenced page — which is the read-only file's page cache page.

**The write bypasses all permission checks entirely.** The attacker has now modified the in-memory contents of a file they have no write access to, and those changes are reflected immediately to any process reading the file.

Since any readable file can be targeted — including SUID binaries — an unprivileged user can overwrite a root-owned executable with malicious code and trigger its execution, achieving full privilege escalation.

---

## Proof of Concept Exploit and Impact Demonstration

The exploit code used is available here: [exploit-1.c](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/blob/main/exploit-1.c)

The exploit has been configured to:
- Replace the root password with `piped`
- Back up `/etc/passwd` to `/tmp/passwd.bak` before modification
- Drop into an elevated root shell
- Restore the original `/etc/passwd` on exit

We are logged into a vulnerable device called **Ilion** as a non-root user **uwu**. The goal is to obtain root access.
As shown in the video below, attempting to access `/etc/passwd` as `uwu` results in a permission denied error.
Running the exploit triggers the race condition, modifies `/etc/passwd` via the dirty page cache, and successfully escalates to a root shell — all from an unprivileged account.

> **[Video: Dirty Pipe PoC — exploitation walkthrough on Ilion as user uwu]**

---

## Patch Analysis

[View the patch commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9d2231c5d74e13b2a0546fee6737ee4446017903)

| Field | Details |
|---|---|
| **Commit ID** | `9d2231c5d74e13b2a0546fee6737ee4446017903` |
| **Commit Title** | `pipe: Fix missing initialization of pipe_buffer.flags` |
| **Author** | Max Kellermann \<max.kellermann@ionos.com\> |
| **Date** | 2022-02-23 |
| **Affected Subsystem** | Pipe / Memory Management |
| **Files Modified** | `fs/pipe.c`, `lib/iov_iter.c` |

### Pipe Buffer Flag Initialisation

In `lib/iov_iter.c`, the patch initializes the previously uninitialized `flags` member of newly allocated `pipe_buffer` structures.

**Before (vulnerable):**
```c
buf->ops    = &page_cache_pipe_buf_ops;
get_page(page);
buf->page   = page;
buf->offset = offset;
buf->len    = bytes;
// flags field never assigned — stale kernel memory value persists
```

Because `pipe_buffer.flags` could contain stale values from previously freed kernel memory, an attacker could inherit `PIPE_BUF_FLAG_CAN_MERGE` without ever explicitly setting it.

**After (patched):**
```c
buf->ops    = &page_cache_pipe_buf_ops;
buf->flags  = 0;   // explicitly cleared
get_page(page);
buf->page   = page;
buf->offset = offset;
buf->len    = bytes;
```

This guarantees that every newly created pipe buffer starts with no flags enabled.

### Fix in `copy_page_to_iter_pipe()`

`copy_page_to_iter_pipe()` creates pipe buffers backed by pages from the page cache.

```c
// Before
buf->ops = &page_cache_pipe_buf_ops;

// After
buf->ops   = &page_cache_pipe_buf_ops;
buf->flags = 0;
```

### Fix in `push_pipe()`

The same initialization is applied to normal pipe buffer creation in `push_pipe()`.

```c
// Before
buf->ops  = &default_pipe_buf_ops;
buf->page = page;

// After
buf->ops   = &default_pipe_buf_ops;
buf->flags = 0;
buf->page  = page;
```

---

## Mitigation Review

### 1. Kernel Update

Updating the kernel is the only complete, foolproof solution. Target versions:

| Branch | Patched Version |
|---|---|
| Mainline | 5.16.11 |
| Stable 5.15 | 5.15.25 |
| Stable 5.10 | 5.10.102 |

### 2. Restrict Local User Access

- Remove unnecessary user accounts
- Restrict SSH access to trusted identities only
- Avoid granting shell access to untrusted users

### 3. File Integrity Monitoring

Monitor SUID binaries and critical configuration files for unauthorized modifications using tools such as:
- **AIDE** — file integrity checker
- **Tripwire** — detects changes to filesystem objects

---

## References

- [NVD CVE Entry — CVE-2022-0847](https://nvd.nist.gov/vuln/detail/CVE-2022-0847)
- [Original disclosure writeup — Max Kellermann (dirtypipe.cm4all.com)](https://dirtypipe.cm4all.com/)
- [Upstream patch commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9d2231c5d74e13b2a0546fee6737ee4446017903)
- [PoC exploit — AlexisAhmed (GitHub)](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/blob/main/exploit-1.c)
- [Linux kernel pipe source — fs/pipe.c](https://elixir.bootlin.com/linux/latest/source/fs/pipe.c)

---
