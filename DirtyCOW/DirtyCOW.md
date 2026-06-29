# Root Cause

## Starting a Process

Other than _init_, all user processes on a Linux system start as a result of _fork()_, and most of the time, _exec()_ is also called to start a new program instead of running a copy of an existing process. A simple example is any command you run in the terminal, such as _ls_ to list directory contents. When you enter _ls_ into a terminal window, the shell calls _fork()_ to create a copy of itself, and then the new copy calls _exec(ls)_ to replace itself with the ls program.

<img width="1569" height="280" alt="image" src="https://github.com/user-attachments/assets/e1a34c20-3531-4f9a-a6ae-80c3150fb5d8" />

## Copy-On-Write

When a process is forked, duplicating every byte of memory is wasteful, especially if the child never modifies most of it. This is solved by Copy-On-Write (COW).
Instead of copying memory immediately, both the parent and child process are pointed to the same physical memory pages, marked read only. The moment either process attempts to write to a shared page, the kernel intercepts the write, creates a private writable copy of that page for the writing process, and lets the write proceed on the copy. The other process continues seeing the original, unmodified page. Pages that are never written to are never copied, thus, saving memory.

## The Vulnerability

**CVE-2016-5195**, known as **Dirty COW**, is a race condition in the Linux kernel's COW implementation that existed from kernel version 2.6.22 (2007) until it was patched in 4.8.3 (2016), a period of nine years.

The vulnerability works as follows:

1. A process memory maps a read only file from disk using _mmap()_ with _MAP_PRIVATE_, meaning writes should go to a private copy, never touching the original file.
Two threads are spawned that race against each other simultaneously.

2. Thread 1 repeatedly writes to the mapped memory via _/proc/self/mem_
Thread 2 repeatedly calls _madvise(MADV_DONTNEED)_, telling the kernel to discard the private COW copy

3. The COW process happens in multiple kernel steps. If Thread 2 discards the private copy between the kernel deciding to write and actually performing the write, the kernel loses track of which page to write to.

4. The write lands on the original file on disk instead of the private copy, bypassing file permissions entirely.
Since any file on the system can be targeted, an unprivileged user can overwrite root owned files such as _/etc/passwd_ or _/etc/shadow_, achieving full privilege escalation.

# Proof Of Concept Exploit

Let us try to write to a file called _important_file.txt_. The file is read only and is owned by owner, _owner_.  
We are signed in as non root user _uwu_. 

<img width="723" height="246" alt="image" src="https://github.com/user-attachments/assets/de691f93-28ec-4628-ba59-8b4159ee60c2" />

As you can see, the file cannot be written to because it is read only. To write to it we will use the DirtyCOW exploit.

We write out the code in a file called cow.c, compile it to an executable as cow, and run it on the file. As you can see, the _important.txt_ got changed even though we were not allowed to write to it.  
Notice that only the first 8 characters were changed.  

<img width="724" height="280" alt="image" src="https://github.com/user-attachments/assets/968acca9-67bf-4b19-90d8-7eafb1af9350" />

# Impact Demonstration

We can now use this to overwrite the /etc/passwd file. We can create a new user called toor, with root like permissions.


# Patch Analysis

# Mitigation Review
