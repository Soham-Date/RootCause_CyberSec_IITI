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

The code can be accessed from [dirtyc0w.c](https://github.com/caldonovan/Dirty-COW-Exploit/blob/master/dirtyc0w.c) 

Let us try to write to a file called _important_file.txt_. The file is read only and is owned by owner, _owner_.  
We are signed in as non root user _uwu_. We use the code in _dirtyc0w.c_ to overwrite this file.

<img width="723" height="246" alt="image" src="https://github.com/user-attachments/assets/de691f93-28ec-4628-ba59-8b4159ee60c2" />

As you can see, the file cannot be written to because it is read only. To write to it we will use the DirtyCOW exploit.

We write out the code in a file called cow.c, compile it to an executable as cow, and run it on the file. As you can see, the _important.txt_ got changed even though we were not allowed to write to it.  
Notice that only the first 8 characters were changed.  

<img width="724" height="280" alt="image" src="https://github.com/user-attachments/assets/968acca9-67bf-4b19-90d8-7eafb1af9350" />

# Impact Demonstration

The code can be accessed from [dirtyuser.c](https://github.com/firefart/dirtycow)

We can now use this to overwrite the /etc/passwd file. We can create a new user called toor, with root like permissions. We use the code from _dirtyuser.c_ to overwrite this file and create a new user called toor to get root permissions.  
We touch a new c file called user.c and compile it.

# Patch Analysis

[View the patch commit](https://git.zx2c4.com/wireguard-linux/commit/?h=devel&id=19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619&utm_source=chatgpt.com)

Commit ID: 19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619  
Commit title: mm: remove gup_flags FOLL_WRITE games from __get_user_pages()  
Author: Linus Torvalds <torvalds@linux-foundation.org>  
Date: 2016-10-13  
Affected subsystem: Memory Management (mm/)  
Files Modified: include/linux/mm.h ; mm/gup.c  

## FOLL_COW

In  
_include/linux/mm.h_:  
_#define FOLL_COW 0x4000_  
was added.  
The patch separates _FOLL_WRITE_ function to indicate completion of COW and assigns it to _FOLL_COW_. This removes the ambiguity of causing race.

## Write validation function

Added:  
_static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
{
    return pte_write(pte) ||
        ((flags & FOLL_FORCE) &&
         (flags & FOLL_COW) &&
         pte_dirty(pte));
}_  

This checks if the writing is actually valid.

## Change in page write validation

_if ((flags & FOLL_WRITE) && !pte_write(pte))_  
was changed to  
_if ((flags & FOLL_WRITE) &&
    !can_follow_write_pte(pte, flags))_  

 Thus, the kernel no longer trusts only the FOLL_WRITE flag and also verifies the actual page state.

 ## COW state tracking

 Removed _FOLL_WRITE_ after COW

 Changed:  
 _if ((ret & VM_FAULT_WRITE) &&  
    !(vma->vm_flags & VM_WRITE))  
      \*flags &= ~FOLL_WRITE;_

To:  
_if ((ret & VM_FAULT_WRITE) &&  
    !(vma->vm_flags & VM_WRITE))  
      \*flags |= FOLL_COW;_
        
# Mitigation Review

1. Updating the kernel to a patched version is the only foolproof solution.
   
2. Reduce the attackers opputunities. DirtyCOW requires local user accounts for escalation
     - avoid unnecessary user accounts
     - restrict shell access
     - enforce least privileges
     - monitor suspicious local processes
       
3. Monitoring sensitive files such as SUIDs and binaries
