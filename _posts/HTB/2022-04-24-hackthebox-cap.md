---
title: "HTB Walkthrough: Cap"
date: 2022-04-24T17:16:30-04:00
categories:
  - HackTheBox
tags:
  - HTB
  - Walkthrough
  - Enumeration
  - Easy
---

![Backdoor Logo](/assets/images/HTB/cap/cap.jpg)

**Welcome** to this walkthrough for the [Hack The Box](https://www.hackthebox.com/) machine Cap. This one is listed as a 'easy' box and has also been retired, so access is only provided to those that have purchased VIP access to HTB.
Because of this, you may notice that it is necessary to be connected to HTB's VIP VPN server, rather than the free server. To do this, change the dropdown selection in the top right corner where you select "Connect"
to "VIP" and download the .ovpn package (yes, even as a paid user, you must toggle between free and paid VPN packages depending on the machine).

---

## Service/Application Enumeration

I went ahead and started my NMap scan and then plugged the IP address into the browser to check for HTTP and HTTPS respectfully: **10.10.11.125:80** & **10.10.11.125:443**

```bash
sudo nmap -sS -A -sV -T4 -p- 10.10.10.245 | tee nmap_full.txt
dirb http://10.10.10.245/ /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt | tee dirb.log
nikto -h "http://10.10.10.245/" | tee nikto.log 
```