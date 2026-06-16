# RootCause_CyberSec_IITI

## LabMac

A VM was created on Microsoft Azure. The VM is named Ilion, another name for the Greek city of Troy. 

We now have a place to safely run our exploits.

## DirtyCOW

### Starting a Process

Other than _init_, all user processes on a Linux system start as a result of _fork()_, and most of
the time, you also run _exec()_ to start a new program instead of running a copy of an existing process. A
very simple example is any program that you run at the command line, such as the _ls_ command to show the
contents of a directory. When you enter _ls_ into a terminal window, the shell that’s running inside the terminal
window calls _fork()_ to create a copy of the shell, and then the new copy of the shell calls _exec(ls)_ to
run _ls_. The figure shows the flow of processes and system calls for starting a program like _ls_.

<img width="1569" height="280" alt="image" src="https://github.com/user-attachments/assets/e1a34c20-3531-4f9a-a6ae-80c3150fb5d8" />

When a process wants to duplicate memory (like when fork() creates a child process), copying every byte is wasteful, especially if the child never modifies most or even any of it.
This problem is solved by COW (Copy-On-Write).

### Copy-On-Write

When a process is forked, both the parent and child point to the same physical memory. In case either process wants to write to this memory page, a writable copy of the memory page is created by the kernel.

### Working of the Exploit

1. DirtyCOW deals with memory mapped files, i.e. a disk file mapped directly into a processes virtual memory.

2. If we try to write to the file, the kernel creates a personal RAM copy and leaves the disk file untouched.

3. Let's say, during this, a thread of this process calls _madvise(MADV_DONTNEED)_, the kernel will then delete this copy.

4. The kernel then get's confused and writes to the original, untouched file.

5. We can now use this to overwrite any files owned by root, even the passwd file

# Environment Setup

# Proof Of Concept Exploit

# Impact Demonstration

# Patch Analysis

# Mitigation Review