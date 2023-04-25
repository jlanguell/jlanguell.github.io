---
title: "HTB Walkthrough: Paper"
date: 2022-04-23T15:20:30-04:00
categories:
  - HackTheBox
tags:
  - HTB
  - Walkthrough
  - Enumeration
  - Easy
---

![Paper Logo](/assets/images/HTB/paper/paper.jpg)

## Service/Application Enumeration

I went ahead and started my NMap scan and then plugged the IP address into the browser to check for HTTP and HTTPS respectfully: **10.10.11.125:80** & **10.10.11.125:443**

```bash
sudo nmap -sS -A -sV -T4 -p- 10.10.11.125 | tee nmap_full.txt
dirb http://10.10.11.125/ /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt | tee dirb.log
nikto -h "http://10.10.11.125/" | tee nikto.log 
```