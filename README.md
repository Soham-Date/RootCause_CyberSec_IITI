# RootCause_CyberSec_IITI

## LabMac

A VM was created on Microsoft Azure. The VM is named Ilion, another name for the Greek city of Troy. 

We now have a place to safely run our exploits.

## DirtyCOW

Other than _init_, all user processes on a Linux system start as a result of _fork()_, and most of
the time, you also run _exec()_ to start a new program instead of running a copy of an existing process. A
very simple example is any program that you run at the command line, such as the _ls_ command to show the
contents of a directory. When you enter ls into a terminal window, the shell that’s running inside the terminal
window calls _fork()_ to create a copy of the shell, and then the new copy of the shell calls _exec(ls)_ to
run _ls_.The figure shows the flow of processes and system calls for starting a program like _ls_.

<img width="907" height="166" alt="image" src="https://github.com/user-attachments/assets/892707c6-53e3-452e-9885-10fd60cc3700" />

When a process wants to duplicate memory (like when _fork()_ creates a child process), copying every bit is inefficient, especially if the child never modifies most or any of it.
The kernel thus, on copies the 
