# Root Cause

## Pipes and Inter Process Communication (IPC)
Linux processes are isolated from each other by design one process cannot directly read or write another's memory. 
To allow processes to communicate, the kernel provides Inter Process Communication (IPC) mechanisms. The pipe is such a mechanism.
A pipe is unidirectional. A process will write into one end of it, and another process will recieve this data from the other end.  
When you run a command like _ls | grep foo_ (foo is computer jargon for 'blah') in a shell, the kernel creates a pipe between the two processes. 
The output of _ls_ flows into the pipe, and _grep_ reads from it.

NOTE: Realistically one would use something like _grep -r "key" foo_, but _ls_ has been used here for demonstration purposes. Please so not come for us.

From the perspective of the kernel, the pipe is a ring buffer. A ring buffer is a circular array of fixed size slots. These slots are called pipe buffers.  
These pipe buffers point to a memory page and contain some metadata on how this information is to be used.

## Page Cache
When a file is read from the disk, the kernel does not read it fresh every time. Instead, it loads the file's contents into a region of memory called the page cache. 
This is a kernel managed pool of memory pages, each holding some file data. 
Subsequent reads of the same file are served directly from the page cache, avoiding reading from the disk repetitively (I had a stroke trying to spell repetitively. It just does not look right).
The kernel controls who can modify these cached pages based on file permissions.

## Splice
Normally, to feed data into a pipe, one would create a copy from the cache page for use in the user space. This is wasteful.
So instead of copying, _splice()_ simply references to the cache page with the file. This is more efficient.  
Each pipe buffer entry tracks this reference with a set of flags that describe what kind of page it is pointing to and what operations are permitted on it.

## The Vulnerability

CVE-2022-0847, known as DirtyPipe, is a flaw in the Linux kernel's pipe buffer flag handling, present from kernel version 5.8 until it was patched in 5.16.11 / 5.15.25 / 5.10.102.  
The vulnerability works as follows:

One of the pipe buffer flags, _PIPE_BUF_FLAG_CAN_MERGE_, signals to the kernel that incoming write data can be merged directly into an existing pipe buffer page, rather than allocating a new one.
When a pipe buffer slot is recycled for reuse, the kernel fails to clear this flag. The old _CAN_MERGE_ flag from a previous operation remains set on the recycled buffer.
An attacker uses _splice()_ to pull data from a read only file into the pipe. Because _splice()_ does not create a copy, the pipe buffer now references the actual page cache page of that file.
The attacker then writes into the pipe. The kernel sees the _CAN_MERGE_ flag is set and, instead of allocating a fresh page, merges the write directly into the referenced page which is the read only file's page cache page.
The write bypasses all permission checks entirely. The attacker has now modified the in memory contents of a file they have no write access to, and those changes are reflected immediately to any process reading the file.

Since any readable file can be targeted including SUID binaries an unprivileged user can overwrite a root owned executable with malicious code and trigger its execution, achieving full privilege escalation.

# Environment Setup

# Proof Of Concept Exploit

# Impact Demonstration

# Patch Analysis

# Mitigation Review
