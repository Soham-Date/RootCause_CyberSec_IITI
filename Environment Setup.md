## Hypervisor
The two types of hypervisors are:  
	1. Bare-metal: Runs directly on hardware and provides better performance. (eg. KVM, Xen, ESXi)
	2. Hosted: Runs on top of a host OS. (eg. VirtualBox, VMware)

## QEMU
A QEMU is a machine emulator. It can emulate an entire CPU/architecture in pure software (slow), or, when paired with KVM, use hardware acceleration and just handle device emulation (disk, network, graphics) while KVM handles CPU virtualization. For our use case (x86_64 Ubuntu VMs on x86_64 hosts), we will use QEMU+KVM together.

## KVM
A kernel based virtual machine (KVM) is a Linux kernel module that turns the kernel itself into a bare-metal hypervisor, using Intel VT-x/AMD-V CPU extensions for near-native VM performance.

## libvirt
libvirt is a management daemon + API that sits above QEMU/KVM (and other hypervisors) and provides a uniform way to define, start, stop, snapshot, and network VMs, regardless of which hypervisor is underneath. It's what actually talks to QEMU; nothing above it needs to know QEMU's CLI syntax.

## virt-manager
The GUI version of virsh. Used to create and manager vitual machines through libvirt

# Setting up virt-manager

## Ubuntu as host

```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager
sudo usermod -aG libvirt,kvm $USER
```

Log out/in and verify:  
```bash
sudo systemctl status libvirtd 
virsh list --all
```

## Arch as host

```bash
sudo pacman -S qemu-emulators-full qemu-desktop libvirt virt-manager dnsmasq
sudo systemctl enable --now libvirtd.socket
sudo usermod -aG libvirt $USER
```

## Setting up the vulnerable machine

Run the virt-manager:  
```bash
virt-manager
```

Click on create a new VM and select the corresponding .iso file of the version you want to install.

The .iso files can be found here:  
[Newer Ubuntu Versions](https://releases.ubuntu.com/)  
[Older Ubuntu Versions](https://old-releases.ubuntu.com/releases/)
[Ubuntu 16.04.1 LTS (Xenial Xerus) for DirtyCOW](https://old-releases.ubuntu.com/releases/xenial/ubuntu-16.04.1-server-amd64.iso)

Use 4096 Mo of RAM with 2 CPU cores with 15 Go for the disk image

**NOTE: AT SOME POINT DURING THE INSTALLATION PROCESS, YOU WILL ASKED IF YOU WANT AUTOMATIC UPDATES. IT IS IMPORTANT THAT YOU SAY NO**
## Adding essential utilities

These exploits require gcc to be installed.  
```bash
sudo apt install gcc
```

It is also recommended to ssh into the machine instead of working on it directly as it is more comfortable to do so.   
```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

Then you log into the VM via your host machine:  
```bash
ssh <ID>@<IP_ADDRESS>
```  
_Replace **ID** with your user ID and **IP_ADDRESS** with the VM IP address_

You will also want to create a unprivileged user using:  
```bash
sudo adduser <username>
```  
You will be prompted for a password. 

## Using different terminals
I am personally using Kitty as my terminal emulator. Thus I will set the shell sessions to fall back to the standard xterm formatting using:  
```bash
echo 'export TERM=xterm-256color' >> ~/.bashrc
source ~/.bashrc
```  
### Troubleshooting
1. Many of the Ubuntu versions (such as 16.04) have reached their end of life and thus have stale repository links. To fix this use:

```bash
echo "91.189.91.124 old-releases.ubuntu.com" | sudo tee -a /etc/hosts
sudo sed -i -r 's/([a-z]{2}\.)?archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
sudo sed -i -r 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
sudo rm -rf /var/lib/apt/lists/*
sudo apt update
```

2. If you can't connect to the internet when using Arch as a host, try running the following commands:

```bash
# Enable IPv4 forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Reset and allow forwarding on virbr0
sudo iptables -P FORWARD ACCEPT
sudo iptables -F FORWARD

# Enable NAT masquerading and TCP MSS clamping (fixes Wi-Fi/MTU packet hanging)
sudo iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE
sudo iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```