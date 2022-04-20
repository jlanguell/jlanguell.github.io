---
title: "HTB Walkthrough: Ransom"
date: 2022-04-18T15:34:30-04:00
categories:
  - HackTheBox
tags:
  - HTB
  - Medium
  - Walkthrough
  - Enumeration
  - PHP
  - API
  - Web Fuzzing
  - Linux
  - Web
  - Cryptography
  - Source Code Review
  - Authentication
  - JSON
  - Laravel
---

![Ransom Logo](/assets/images/HTB/ransom/ransom.jpg)

**Welcome** to this walkthrough for the [Hack The Box](https://www.hackthebox.com/) machine Ransom. This one is listed as a 'medium' box and has also been retired, so access is only provided to those that have purchased VIP access to HTB.
Because of this, you may notice that it is necessary to be connected to HTB's VIP VPN server, rather than the free server. To do this, change the dropdown selection in the top right corner where you select "Connect"
to "VIP" and download the .ovpn package (yes, even as a paid user, you must toggle between free and paid VPN packages depending on the machine).

## Service Enumeration

Start by connecting to the VPN server and fire up the box. After a couple minutes, we can ping it to make sure its online and then proceed with our simple network scans:

> Note: I checked for ports 80 and 443 first by punching **10.10.11.153:80** and **10.10.11.152:443** into my web browser. Since port 80, HTTP pulled up a website, I know to start scans to enumerate this service. 

```bash
$ sudo nmap -sS -A -sV -T4 -p- 10.10.11.153 | tee nmap_full.txt
$ nikto -h "http://10.10.11.153/" | tee nikto.log
$ dirb http://10.10.11.153/ /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt | tee dirb.log
```
To Be Continued...
