Tp1 - b2a - réseau : Graig KOLODZIEJCZYK

1)
A)
user@MacBook-Pro-de-User ~ % ifconfig
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000 
	inet6 ::1 prefixlen 128 
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 
	nd6 options=201<PERFORMNUD,DAD>
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
stf0: flags=0<> mtu 1280
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400<CHANNEL_IO>
	ether 18:65:90:d3:c3:31 
	inet6 fe80::14bd:9d28:7fc7:ecff%en0 prefixlen 64 secured scopeid 0x4 
	inet 10.33.3.127 netmask 0xfffffc00 broadcast 10.33.3.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active

user@MacBook-Pro-de-User ~ % route -n get default
   route to: default
destination: default
       mask: default
    gateway: 10.33.3.253 
interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0 
2)
B)

user@MacBook-Pro-de-User ~ % arp -a
? (10.33.0.7) at 9c:bc:f0:b6:1b:ed on en0 ifscope [ethernet]
? (10.33.0.42) at ce:a6:a5:8c:f3:7a on en0 ifscope [ethernet]
? (10.33.0.48) at 54:4e:90:3c:33:3f on en0 ifscope [ethernet]
? (10.33.0.96) at ca:4f:f4:af:8f:c on en0 ifscope [ethernet]
? (10.33.0.99) at e0:cc:f8:99:2b:27 on en0 ifscope [ethernet]
? (10.33.0.111) at d2:41:f0:dc:6a:ed on en0 ifscope [ethernet]
? (10.33.0.180) at 26:91:29:98:e2:9d on en0 ifscope [ethernet]
? (10.33.0.229) at a4:83:e7:69:d6:63 on en0 ifscope [ethernet]
? (10.33.0.245) at 84:fd:d1:f1:23:7c on en0 ifscope [ethernet]
? (10.33.1.54) at 30:d1:6b:26:5:63 on en0 ifscope [ethernet]
? (10.33.1.117) at 3e:f:17:bb:bc:8a on en0 ifscope [ethernet]
? (10.33.1.208) at b2:dd:d8:d4:94:6c on en0 ifscope [ethernet]
? (10.33.3.50) at 38:87:d5:d7:71:2a on en0 ifscope [ethernet]
? (10.33.3.59) at 2:47:cd:3d:d4:e9 on en0 ifscope [ethernet]
? (10.33.3.88) at 4c:2:20:4b:a9:d9 on en0 ifscope [ethernet]
? (10.33.3.189) at c2:6f:43:3d:c7:fa on en0 ifscope [ethernet]
? (10.33.3.226) at 5c:3a:45:6:7a:5f on en0 ifscope [ethernet]
? (10.33.3.253) at 0:12:0:40:4c:bf on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]

user@MacBook-Pro-de-User ~ % ping 10.33.3.253
PING 10.33.3.253 (10.33.3.253): 56 data bytes
64 bytes from 10.33.3.253: icmp_seq=0 ttl=255 time=22.187 ms
64 bytes from 10.33.3.253: icmp_seq=1 ttl=255 time=22.846 ms

user@MacBook-Pro-de-User ~ % ping 1.1.1.1
PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=58 time=50.853 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=44.474 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=27.283 ms

user@MacBook-Pro-de-User ~ % ping google.com
PING google.com (216.58.214.174): 56 data bytes
64 bytes from 216.58.214.174: icmp_seq=0 ttl=114 time=53.326 ms
64 bytes from 216.58.214.174: icmp_seq=1 ttl=114 time=24.451 ms
`64 bytes from 216.58.214.174: icmp_seq=2 ttl=114 time=48.675 ms
64 bytes from 216.58.214.174: icmp_seq=3 ttl=114 time=51.542 ms
64 bytes from 216.58.214.174: icmp_seq=4 ttl=114 time=43.478 ms
64 bytes from 216.58.214.174: icmp_seq=5 ttl=114 time=44.286 ms

user@MacBook-Pro-de-User ~ % ping 10.33.3.253
PING 10.33.3.253 (10.33.3.253): 56 data bytes
64 bytes from 10.33.3.253: icmp_seq=0 ttl=255 time=24.505 ms
64 bytes from 10.33.3.253: icmp_seq=1 ttl=255 time=10.019 ms
64 bytes from 10.33.3.253: icmp_seq=2 ttl=255 time=35.242 ms


C)

user@MacBook-Pro-de-User ~ % nmap
Nmap 7.92 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports consecutively - don't randomize
  --top-ports <number>: Scan <number> most common ports
  --port-ratio <ratio>: Scan ports more common than <ratio>
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --append-output: Append to rather than clobber specified output files
  --resume <filename>: Resume an aborted scan
  --noninteractive: Disable runtime interactions via keyboard
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (https://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES

user@MacBook-Pro-de-User ~ % ifconfig
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000 
	inet6 ::1 prefixlen 128 
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 
	nd6 options=201<PERFORMNUD,DAD>
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
stf0: flags=0<> mtu 1280
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400<CHANNEL_IO>
	ether 18:65:90:d3:c3:31 
	inet6 fe80::14bd:9d28:7fc7:ecff%en0 prefixlen 64 secured scopeid 0x4 
	inet 10.33.3.58 netmask 0xfffffc00 broadcast 10.33.3.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active

user@MacBook-Pro-de-User ~ % ping 10.33.3.253
PING 10.33.3.253 (10.33.3.253): 56 data bytes
64 bytes from 10.33.3.253: icmp_seq=0 ttl=255 time=14.946 ms
64 bytes from 10.33.3.253: icmp_seq=1 ttl=255 time=9.968 ms
64 bytes from 10.33.3.253: icmp_seq=2 ttl=255 time=14.957 ms


Pas trouvé pourquoi ping 1.1.1.1 ou 8.8.8.8 n’a pas fonctionné je passe A la suite ….

D) pas de cable RJ45 je suis avec Clément et Arthur explication + visuel

## II. Exploration locale en duo

### ­ƒî×Si vos PCs ont un port RJ45 alors y'a une carte r├®seau Ethernet associ├®e

## 3. Modification d'adresse IP

```bash
Ô×£  ~ arp | grep 192.168.10
192.168.10.1             ether   98:28:a6:2c:17:f0   C                     enx44a92c500340

Ô×£  ~ ip a
11: enx44a92c500340: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 44:a9:2c:50:03:40 brd ff:ff:ff:ff:ff:ff
    inet 192.168.10.2/30 brd 192.168.10.3 scope global noprefixroute enx44a92c500340
       valid_lft forever preferred_lft forever
    inet6 fe80::21af:d2f4:7fda:1bde/64 scope link noprefixroute
       valid_lft forever preferred_lft forever

Ô×£  ~ ping 192.168.10.1 -c2
PING 192.168.10.2 (192.168.10.2) 56(84) bytes of data.
64┬áoctets de 192.168.10.2┬á: icmp_seq=1 ttl=64 temps=0.068┬áms
64┬áoctets de 192.168.10.2┬á: icmp_seq=2 ttl=64 temps=0.063┬áms

--- statistiques ping 192.168.10.2 ---
2┬ápaquets transmis, 2 re├ºus, 0┬á% paquets perdus, temps 1031┬áms
rtt min/avg/max/mdev = 0.063/0.065/0.068/0.002 ms
```

## 4. Utilisation d'un des deux comme gateway

sudo ifconfig wlp0s20f3 down

Ô×£  ~ ping 192.168.10.1 -c2
PING 192.168.10.1 (192.168.10.1) 56(84) bytes of data.
64┬áoctets de 192.168.10.1┬á: icmp_seq=1 ttl=128 temps=1.11┬áms
64┬áoctets de 192.168.10.1┬á: icmp_seq=2 ttl=128 temps=0.880┬áms

--- statistiques ping 192.168.10.1 ---
2┬ápaquets transmis, 2 re├ºus, 0┬á% paquets perdus, temps 1001┬áms
rtt min/avg/max/mdev = 0.880/0.993/1.106/0.113 ms

Ô×£  ~ ip r | grep default
default via 192.168.10.1 dev enx44a92c500340 proto static metric 100

### ­ƒî× pour tester la connectivit├® ├á internet on fait souvent des requ├¬tes simples vers un serveur internet connu

```bash
Ô×£  ~ ping -c4 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64┬áoctets de 8.8.8.8┬á: icmp_seq=1 ttl=114 temps=19.9┬áms
64┬áoctets de 8.8.8.8┬á: icmp_seq=2 ttl=114 temps=19.3┬áms
64┬áoctets de 8.8.8.8┬á: icmp_seq=3 ttl=114 temps=20.6┬áms
64┬áoctets de 8.8.8.8┬á: icmp_seq=4 ttl=114 temps=17.8┬áms

--- statistiques ping 8.8.8.8 ---
4┬ápaquets transmis, 4 re├ºus, 0┬á% paquets perdus, temps 3005┬áms
rtt min/avg/max/mdev = 17.788/19.395/20.603/1.035 ms
```

### ­ƒî× utiliser un traceroute ou tracert pour bien voir que les requ├¬tes passent par la passerelle choisie (l'autre le PC)

```bash
Ô×£  ~ traceroute 8.8.8.8
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  _gateway (192.168.137.1)  0.581 ms  0.486 ms  0.448 ms
 2  * * *
 3  _gateway (10.33.3.253)  4.615 ms  6.566 ms  8.490 ms
 4  10.33.10.254 (10.33.10.254)  8.199 ms  8.582 ms  9.745 ms
 5  reverse.completel.net (92.103.174.137)  10.634 ms  13.566 ms  13.850 ms
 6  92.103.120.182 (92.103.120.182)  15.610 ms  9.026 ms  9.270 ms
 7  172.19.130.117 (172.19.130.117)  18.431 ms  23.411 ms  23.367 ms
 8  46.218.128.74 (46.218.128.74)  19.149 ms  19.282 ms  22.360 ms
 9  38.147.6.194.rev.sfr.net (194.6.147.38)  22.840 ms  22.626 ms  23.455 ms
10  72.14.194.30 (72.14.194.30)  21.690 ms  22.703 ms  17.326 ms
11  * * *
12  dns.google (8.8.8.8)  33.396 ms  30.249 ms  31.058 ms
```

## 5. Petit chat priv├®

### ­ƒî× sur le PC serveur avec l'IP 192.168.137.2

```bash
Ô×£  ~ netcat -l -p 8888
salut
L├®o c'est le plus beau
tu trouves ? jprefere devilledon
Oh le batart
allez jme casse t'as des gouts de chiottes
```

### ­ƒî× sur le PC client avec l'IP 192.168.137.1

commande de cl├®ment : (c'est lui le client) : `nc.exe 192.168.137.2 8888`

### ­ƒî× pour aller un peu plus loin

commande de cl├®ment : (c'est lui le serveur) : `nc.exe -l -p 192.168.137.2 8888`

```bash
... (4 lignes restantes)
Ô×£  ~ netcat 192.168.137.1 8888
hello
ciao !
```


## III. Manipulation d'autres outils/protocoles côté client

## DHCP

user@MacBook-Pro-de-User ~ % networksetup -listallhardwareports
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 18:65:90:d3:c3:31

Hardware Port: Bluetooth PAN
Device: en3
Ethernet Address: 18:65:90:d3:c3:32

Hardware Port: Thunderbolt 1
Device: en1
Ethernet Address: 82:13:21:6d:7b:00

Hardware Port: Thunderbolt 2
Device: en2
Ethernet Address: 82:13:21:6d:7b:01

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 82:13:21:6d:7b:00

VLAN Configurations

je ne pense pas que se soit ca mais j'ai essayer de trouver la date sans d'expiration sans reponse malheureusement 

## 2. DNS

user@MacBook-Pro-de-User ~ % nslookup google.com
Server:		10.33.10.2
Address:	10.33.10.2#53

Non-authoritative answer:
Name:	google.com
Address: 216.58.214.174

user@MacBook-Pro-de-User ~ % nslookup ynov.com
Server:		10.33.10.2
Address:	10.33.10.2#53

Non-authoritative answer:
Name:	ynov.com
Address: 92.243.16.143

user@MacBook-Pro-de-User ~ % nslookup 78.74.21.21
Server:		10.33.10.2
Address:	10.33.10.2#53

Non-authoritative answer:
21.21.74.78.in-addr.arpa	name = host-78-74-21-21.homerun.telia.com.

Authoritative answers can be found from:

user@MacBook-Pro-de-User ~ % nslookup 92.146.54.88
Server:		10.33.10.2
Address:	10.33.10.2#53

Non-authoritative answer:
88.54.146.92.in-addr.arpa	name = apoitiers-654-1-167-88.w92-146.abo.wanadoo.fr.

Authoritative answers can be found from:

## IV. Wireshark

J'ai pu télécharger WireShark sur mon Mac je l'ai ouvert et y'a plus de 3000 lignes qui se sont activé des ip etc... apparut je sais pas trop quoi te copier coller 
et je préfère pas toucherau logiciel ne sachant pas comment il fonctionne en espérant avoir un petit cour avec toi pour capter se qui se passe sur mon écran,
vu qu'on va l'utiliser assez souvent de ce que j'ai compris, je referais cette partie une fois que tu nous montrera le tp plus détaillé ;)


Cordialement 

Graig KOLODZIEJCZYK
