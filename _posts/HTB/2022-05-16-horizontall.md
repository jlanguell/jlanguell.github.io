---
title: "HTB Walkthrough: Horizontall"
date: 2022-05-16T22:46:30-04:00 
categories:
  - HackTheBox
header:
  teaser: /assets/images/HTB/horizontall/horizontall.png
tags:
  - Easy
  - Linux Host
---

![Antique Logo](/assets/images/HTB/horizontall/horizontall.png)  

---

## Scanning  

Let's go ahead and run our port scanner.    

### NMap Results  

```bash
$ sudo nmap -sS -A -sV -T5 -p- 10.10.11.105 | tee nmap.log

22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
```  

### FFUF Results  

```bash
#                       [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 82ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 82ms]
# Copyright 2007 James Fisher [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 82ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 83ms]
# on at least 2 different hosts [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 82ms]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 83ms]
#                       [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 83ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 83ms]
                        [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 88ms]
#                       [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 88ms]
img                     [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 91ms]
#                       [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 91ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 90ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 90ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 91ms]
css                     [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 86ms]
js                      [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 94ms]
                        [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 76ms]
```  


