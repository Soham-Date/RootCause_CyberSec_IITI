# RootCause_CyberSec_IITI SoC 2026

RootCause is an educational Linux vulnerability research platform that will enable teams to reproduce, analyse, and document real-world CVEs in fully isolated environments.
The project aims to bridge the gap between theoretical knowledge of privilege escalation and memory corruption vulnerabilities and hands-on exploitation workflows used by professional penetration testers.

## Problem Statement

Linux systems underpin the modern internet, from cloud servers to embedded devices, yet have repeatedly suffered critical vulnerabilities. 
Exploits such as Dirty COW, DirtyPipe, and PwnKit demonstrate how small implementation flaws can lead to full system compromise. 
Despite the availability of CVE databases and write-ups, most people lack a structured, hands-on workflow for understanding why these vulnerabilities exist, how they are exploited, and how they are fixed.
RootCause addresses this gap by building a complete research and analysis environment around real Linux CVEs, paired with a lightweight reconnaissance utility.

## Proposed Features

### Core CVE Analysis Modules
For each selected vulnerability, the team will deliver the following:
- Root Cause Analysis : Identify and explain the exact code flaw: race condition, unchecked pointer, improper privilege validation, etc.  
- Isolated Environment Setup : Reproducible Docker or QEMU environment pinned to the vulnerable kernel or package version.  
- Proof-of-Concept Exploit : Working PoC with line-by-line commentary explaining each exploitation stage.  
- Impact Demonstration : Show privilege escalation or system compromise resulting from successful exploitation.  
- Patch Analysis : Identify the fixing commit, explain what changed, and discuss why it closes the vulnerability.  
- Mitigation Review : Document workarounds such as kernel hardening flags, SELinux policies, or package updates available before the patch.

### Target CVEs
| Identifier | Common Name | Vulnerability Type |
| :--- | :--- | :--- |
| CVE-2016-5195 | DirtyCOW | Race around in copy-on-write memory |
| CVE-2021-4034 | PwnKit | Argument parsing flaw in pkexec |
| CVE-2022-0847 | DirtyPipe | Pipe buffer flag misuse, file overwrite |
| CVE-2026-31431 | Copy Fail | Kernel copy-on-write corruption |
| CVE-2026-43284 | DirtyFrag | Memory fragmentation kernel exploit |
