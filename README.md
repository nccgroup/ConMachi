# Conmachi Container Scanner
## Is It Wrong To Pick Up Capabilities In A Container?

Conmachi is a tool written in GO intended to be used to collect information about a container environment and list potential security issues. It can be statically compiled so that it can be dropped into a container environment and run without any dependencies.

## Building

Dependencies:

~~~
sudo apt-get install libpcap-dev
~~~

Conmachi is intended to be built on any LTS version of Ubuntu. In development, it has been built with Go version 1.9 and above but should compile with most versions.

You can statically build the tool with the following commands:

~~~
go get github/TKTK
go get ./...
cd $GOPATH/bin

# Dynamically compile
CGO_LDFLAGS="/usr/lib/x86_64-linux-gnu/libpcap.a" go build conmachi
# OR statically compile, may cause issues with network scanning
CGO_LDFLAGS="/usr/lib/x86_64-linux-gnu/libpcap.a" go build -ldflags '-w -extldflags "-static"' conmachi
~~~

## What it checks for

Conmachi scans for a large number of potential issues including:

* Disabled process and user namespacing
* Dangerous capabilities
* Disabled Seccomp/AppArmor profiles
* Devices mounted from the host

It also collects information that may be useful while exploring a container including:

* Kernel version
* All capability sets with decoded values
* Detect container solution
* Sniff network interface for other hosts

Currently in progress:

* Scan for Kubernetes related issues
* Scan for cloud provider related issues

## Flags

~~~
Usage of ./conmachi:
  -l string
        File to log to
  -sniff int
        Sniff the network for IP addresses for a given number of seconds
~~~

## Example

Let's walk through running Conmachi in a Docker container. To start, we have our working directory with a copy of Conmachi in it:

~~~
$ ls
conmachi
~~~

Then let's add a Dockerfile:

~~~
FROM ubuntu

WORKDIR /example
ADD . /example
~~~

And build it:

~~~
$ ls
conmachi   Dockerfile
$ docker build -t example
~~~

And run it with a scary capability:

~~~
$ docker run --rm --security-opt seccomp=unconfined --security-opt apparmor:unconfined --cap-add SYS_ADMIN -it example
root@ffffffffffff:/example# ./conmachi 
Container has dangerous capabilities
------------------------------------
* Container has capabilities in the CapBnd set which could enable network attacks if a process runs with uid=0: CAP_NET_RAW
* Container has capabilities in the CapEff which could enable network attacks at the current privilege level: CAP_NET_RAW
* Container has dangerous capabilities in the CapBnd set which may allow for container escape if a process runs with uid=0: CAP_SYS_ADMIN
* Container has dangerous capabilities in the CapEff set which may allow for container escape if a process runs at the current privilege level: CAP_SYS_ADMIN


Container has non-default Docker capabilities
---------------------------------------------
Container has non-default Docker capabilities: CAP_SYS_ADMIN

Writeable Mounts
----------------
Some paths are mounted with write permission and may be filesystems mounted from the host. If this is the case, modifying the files at these paths may allow a contained process to modify files outside of the contained environment. The following paths were detected to be mounted with write permissions:
---
Device: /dev/sda1
Path: /etc/resolv.conf
Type: ext4
Opts: [rw relatime data=ordered]
Freq: 0
Pass: 0
---
Device: /dev/sda1
Path: /etc/hostname
Type: ext4
Opts: [rw relatime data=ordered]
Freq: 0
Pass: 0
---
Device: /dev/sda1
Path: /etc/hosts
Type: ext4
Opts: [rw relatime data=ordered]
Freq: 0
Pass: 0
---


User Namespace Disabled
-----------------------
User namespacing is not enabled. As a result, if a contained process is running with uid=0 it will be running as a privileged user if it gains access to resources outside of the container.

Container Running Unconfined AppArmor Profile
---------------------------------------------
Container is not enforcing an AppArmor profile on contained processes

Seccomp is Disabled
-------------------
Seccomp is disabled in container

Processor Vulnerable to Hardware Attacks
----------------------------------------
The following processors have bugs which may be exploited. More information about each of the processors can be found by reading /proc/cpuinfo.

Processor 0 (Intel(R) Core(TM) i7-5557U CPU @ 3.10GHz) bugs: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf
Processor 1 (Intel(R) Core(TM) i7-5557U CPU @ 3.10GHz) bugs: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf


Container Capabilities
----------------------
CapInh (00000000a82425fb): CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_CHROOT, CAP_SYS_ADMIN, CAP_MKNOD, CAP_AUDIT_WRITE, CAP_SETFCAP, CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_AUDIT_READ
CapPrm (00000000a82425fb): CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_CHROOT, CAP_SYS_ADMIN, CAP_MKNOD, CAP_AUDIT_WRITE, CAP_SETFCAP, CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_AUDIT_READ
CapEff (00000000a82425fb): CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_CHROOT, CAP_SYS_ADMIN, CAP_MKNOD, CAP_AUDIT_WRITE, CAP_SETFCAP, CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_AUDIT_READ
CapBnd (00000000a82425fb): CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_CHROOT, CAP_SYS_ADMIN, CAP_MKNOD, CAP_AUDIT_WRITE, CAP_SETFCAP, CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_AUDIT_READ
CapAmb (0000000000000000):


Cgroup Policy Does Not Restrict CPU Usage
-----------------------------------------
Processes in the conainer are capable of using excessive amounts of CPU time

Cgroup Policy Allows for Excessive Memory Usage
-----------------------------------------------
Processes in the conainer are capable of using excessive amounts (>8GB) of RAM

Detected Container Runtime
--------------------------
Container runtime: docker

Kernel Version Info
-------------------
Linux version 4.4.0-134-generic (buildd@lgw01-amd64-033) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #160-Ubuntu SMP Wed Aug 15 14:58:00 UTC 2018

~~~

Cool! It caught our disabled profiles, our dangerous capability, and collected a bunch of info about the environment.