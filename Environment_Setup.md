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

A local virtual machine was created using virt-manager to replicate a vulnerable environment, since cloud providers such as Microsoft Azure no longer offer sufficiently old Ubuntu images on free/student tiers.Download the vulnerable ISO from the official Ubuntu releases archive: [Ubuntu 12.04.4 server (AMD64/EM64T)](https://old-releases.ubuntu.com/releases/12.04/ubuntu-12.04.4-server-amd64.iso), [Ubuntu 12.04.4 server (Intel x64)](https://old-releases.ubuntu.com/releases/12.04/ubuntu-12.04.4-server-i386.iso), [Ubuntu 20.04.1](https://cdimage.ubuntu.com/ubuntu-legacy-server/releases/20.04/release/)

_If nothing pops up on clicking the link, copy the link and paste in a new tab._

In virt-manager:

1. Click New VM
2. Select Local install media (ISO)
3. Browse to _ubuntu-16.04.1-desktop-amd64.iso_ and select it
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

OS: Ubuntu 12.04.4 LTS  
Kernel: 3.11.0-15-generic (unpatched)  
RAM: 2048 Mo  
Disk: 20 Go (Virtual)  
Network: None (isolated)

### Verifying The Vulnerable Kernel

After booting into the kernel, verify:  
_uname -r_

The output should be:  
_3.11.0-15-generic_

This confirms the kernel is within the vulnerable range.  
And again, **do not run _apt-get upgrade_ at any point as doing so would patch the kernel and eliminate the vulnerability. Update refreshes the package lists but upgrades will probably patch the kernel**

### Installing Build Tools

Only _gcc_ is required in the VM to compile the exploit, but Ubuntu 12.04.4 LTS is EOL, so the normal Ubuntu mirrors no longer carry packages. You need to point apt to old-releases.ubuntu.com

Edit your sources:  
_sudo nano /etc/apt/sources.list_  
clear out all the text and replace it with:  
_deb http://old-releases.ubuntu.com/ubuntu/ precise main restricted universe multiverse  
deb http://old-releases.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse  
deb http://old-releases.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse_

Then:  
_sudo apt-get clean  
sudo apt-get update_

_sudo apt-get install gcc -y_

Verify:  
_gcc --version_

Output:  
_gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609_

## Non Root

We need a non root user to run our exploits. To do this either use the Ubuntu GUI or use the CLI.

CLI:  
_sudo useradd -m -s /bin/bash -p $(openssl passwd -1 "yourpassword") username_

replace _yourpassword_ with your password and _username_ with your username.

## SSH Login

For the sake of convenience, I will be using my personal computer to SSH into the vulnerable VM as non root.

To do this we first need ssh service on the VM:  
_sudo apt install openssh-server_

To start ssh server:  
_sudo systemctl enable --now ssh_

To stop ssh server:  
_sudo systemctl disable --now ssh_

Now, we need the host IP:  
_hostname -I_  
it looks something like 192.168.*.*

The output is the IP address. For more information, use:  
_ip addr_

To ssh into your machine use:
_ssh username@IP_

replace username with the username on your vulnerable machine and IP with the IP address.  
It will ask you for the password for the username.  
If you ssh into a new mchine, you will get a warning about the authenticity of the host and will ask you to confirm, type 'yes'.
