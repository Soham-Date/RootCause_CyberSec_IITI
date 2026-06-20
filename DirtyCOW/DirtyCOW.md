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

# Environment Setup

## Host Machine

OS: Ubuntu 26.04 LTS  
Hypervisor: QEMU/KVM via virt-manager

### Instaling Virtual Manager

Use:  
_sudo apt update  
sudo apt install qemu-system-x86 qemu-utils virt-manager -y  
sudo usermod -aG libvirt $USER  
sudo usermod -aG kvm $USER_

Log out and then back in for the groupd to update, then:  
_sudo systemctl start libvirtd  
sudo systemctl enable libvirtd_

Then launch virt-manager:  
_virt-manager_

### Setting Up The Vulnerable VM

A local virtual machine was created using virt-manager to replicate a vulnerable environment, since cloud providers such as Microsoft Azure no longer offer sufficiently old Ubuntu images on free/student tiers.Download the vulnerable ISO from the official Ubuntu releases archive: [Ubuntu 16.04.7 Server AMD64](https://releases.ubuntu.com/16.04/ubuntu-16.04.7-server-amd64.iso)

In virt-manager:

1. Click New VM
2. Select Local install media (ISO)
3. Browse to _ubuntu-16.04.7-server-amd64.iso_ and select it
4. Set RAM to 2048 Mo, CPUs to 2
5. Set disk size to 20 Go
6. Click Finish and proceed through the Ubuntu installer

_During installation:  
Skip network configuration, no internet needed  
Use Guided partitioning, use entire disk  
Do not encrypt the home directory  
Select only standard system utilities and SSH when prompted for software_

**NOTE: DO NOT RUN _apt upgrade_  
TO QUIT THE VM USE _sudo poweroff_**

OS: Ubuntu 16.04.07 LTS  
Kernel: 4.4 (unpatched)  
RAM: 2048 Mo  
Disk: 20 Go (Virtual)  
Network: None (isolated)

### Verifying The Vulnerable Kernel

After booting into the kernel, verify:  
_uname -r_

The output should be:  
_4.4.0-xx-generic_

This confirms the kernel is within the vulnerable range.  
And again, **do not run _apt upgrade_ at any point as doing so would patch the kernel and eliminate the vulnerability.**

### Installing Build Tools

Only _gcc_ is required in the VM to compile the exploit:  
_sudo apt install gcc -y_

Verify:  
_gcc --version_

Output:  
_gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609_

# Proof Of Concept Exploit

# Impact Demonstration

# Patch Analysis

# Mitigation Review
