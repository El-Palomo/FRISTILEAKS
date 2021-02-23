# FRISTILEAKS
Desarrollo del CTF FRISTILEAKS 1.3
Download: https://www.vulnhub.com/entry/fristileaks-13,133/

## Escaneo de puertos
1. Escaneamos todos los puertos de red.

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 192.168.78.138
Nmap scan report for 192.168.78.138
Host is up (0.00055s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13
Network Distance: 1 hop
```

## Enumeración de archivos y carpetas
1. Debido a que solo encontramos el puertos TCP/80 buscamos carpetas y/o archivos.
```
root@kali:~/FRISTILEAKS# gobuster dir -u http://192.168.78.138/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.78.138/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/22 20:54:10 Starting gobuster
===============================================================
/images (Status: 301)
/beer (Status: 301)
===============================================================
2021/02/22 20:54:58 Finished
```











