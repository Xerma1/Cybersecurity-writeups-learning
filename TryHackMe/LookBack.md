# LookBack

![alt](https://i.imgur.com/hUp8Qi7.png)

"The Lookback company has just started the integration with Active Directory. Due to the coming deadline, the system integrator had to rush the deployment of the environment. Can you spot any vulnerabilities?"<br>

We are tasked to find 3 flags. Let's find them!

![alt](https://i.imgur.com/JXaJwyD.png)
 
### Overall attack methodology
- Port scanning for open ports (identify the services running on the system)
- Directory enumeration (since this is an active directory)
- See if there are any vulnerabilities to exploit (unusual directories from testing, outdated services).

## Port scanning
`nmap -Pn -n -p- -sCV -T4 10.48.185.220`<br>

- -Pn is "No ping". It is stated that the VM doesn't accept ICMP packets
- -n is "no DNS resolution". Speeds up scans
-  -p- is "scans all ports from 1 - 65535"
-  -sCV is version detection and script scan
-  -T4 to speed up scanning <br>

### Results
```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-14 13:31 GMT
Nmap scan report for 10.48.185.220
Host is up (0.00023s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
443/tcp  open  ssl/https
|_http-server-header: Microsoft-IIS/10.0
| http-title: Outlook
|_Requested resource was https://10.48.185.220/owa/auth/logon.aspx?url=https%3a%2f%2f10.48.185.220%2fowa%2f&reason=0
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7
| Subject Alternative Name: DNS:WIN-12OUO7A66M7, DNS:WIN-12OUO7A66M7.thm.local
| Not valid before: 2023-01-25T21:34:02
|_Not valid after:  2028-01-25T21:34:02
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: WIN-12OUO7A66M7
|   DNS_Domain_Name: thm.local
|   DNS_Computer_Name: WIN-12OUO7A66M7.thm.local
|   DNS_Tree_Name: thm.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-14T13:33:22+00:00
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7.thm.local
| Not valid before: 2026-03-13T13:28:16
|_Not valid after:  2026-09-12T13:28:16
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.39 seconds
```
We discover 3 open ports: 80, 443 and 3389. We see a url in the HTTPS protcol `https://10.48.185.220/owa/auth/logon.aspx?url=https%3a%2f%2f10.48.185.220%2fowa%2f&reason=0`

![alt](https://i.imgur.com/9wIV3tg.png)

Looks like a login page. Trying admin:admin doesn't really work. Hmm whatever, I will do directory enumeration first to discover some subdirectories.

## Subdirectory enumeration
`gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -u 10.48.185.220 --exclude-length 0`<br>

We use gobuster for this task. `dir` sets it to directory enumeration mode.

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.48.185.220
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/TEST                 (Status: 403) [Size: 1233]
/Test                 (Status: 403) [Size: 1233]
/ecp                  (Status: 302) [Size: 209] [--> https://10.48.185.220/owa/auth/logon.aspx?url=https%3a%2f%2f10.48.185.220%2fecp&reason=0]
/test                 (Status: 403) [Size: 1233]
Progress: 20473 / 20474 (100.00%)
[ERROR] Get "http://10.48.185.220/sapi": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
===============================================================
Finished
===============================================================
```

We find 4 subdirectories! 3 of them are the "test" directory. Verry sus. Let's hop on to one of them: `https://10.48.185.220/TEST`<br>

![alt](https://i.imgur.com/iaPt74f.png)

Oh? A login popup? Let's try the admin:admin default credentials.<br>

![alt](https://i.imgur.com/8FNrAkS.png)

Well, we find out first flag! We are given an interface to run commands on, this is a massive vulnerability. With this, we can try to inject a reverse shell script into the server to get the shell running on our local machine! I used https://www.revshells.com/ for this task.<br>

Playing with command injection into the interface:

![alt](https://i.imgur.com/CTaPWP6.png)

The injection was a success! Now we just have to set up the listener, replace `whoami` with the base64 encoded reverse shell command: <br> 

![alt](https://i.imgur.com/U0jy3zm.png)

and click run!

![alt](https://i.imgur.com/9pblGDq.png)

Success! We are now running Shell on the remote machine. After exploring the file directories for a while, I found the second flag!<br>

![alt](https://i.pinimg.com/736x/d6/16/75/d6167536fcd5561850d86ed597a12cf5.jpg)

The `TODO.txt` has something interesting in it as well:
```
Hey dev team,

This is the tasks list for the deadline:

Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer[TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]


When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local
```

Key things that is of interest: the MS Exchange is not updated with the security update and we have a bunch of emails. Microsoft Exchange Server is a mail server and calendaring server that provides businesses with a comprehensive infrastructure for email, calendar management, contact organization, task tracking, and collaboration. With these information, this implies that the MS Exchange is outdated and has security vulnerabilities that we might discover.<br>

Let't take a look at the version of the MS Exchange.
```
PS C:\Users\dev\Desktop> (Get-Command ExSetup.exe).FileVersionInfo.ProductVersion
15.02.0858.005
```

We have the version number, doing a quick google search reveals the name of the build:

![alt](https://i.pinimg.com/736x/1c/c6/37/1cc637e6eba61bea28c7d00ccb6beb64.jpg)

After ChatGPTing, we discover that this build has a critical vulnerability: Remote Code Execution (RCE). As of this writeup, I have no idea how this exploit works. So I use Metasploit, a pentesting framwork that has hundred of exploits and payloads, all we have to do is set up some parameters and hit run.

```
msfconsole
search exchange rce

10  exploit/windows/http/exchange_proxyshell_rce                  2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE
   11    \_ target: Windows Powershell                               .                .          .      .
   12    \_ target: Windows Dropper                                  .                .          .      .
   13    \_ target: Windows Command                                  .     

```
Running these commands:<br>

![alt](https://i.pinimg.com/736x/0c/7c/1f/0c7c1f6795946c3d6654e0c83b37aeab.jpg)

Exploit ran successfully! We are now running shell as the user NT AUTHORITY/SYSTEM. Seems like a rather privileged user lul.<br>

Within `c:\Users\Administrator\Documents`, we find `flag.txt`. Catting it out, we get out final flag: `THM{Looking_Back_Is_Not_Always_Bad}`.

# Reflection
This THM room taught me the basic atttack methodogy for pentesting systems: port scanning for open services (nmap), enumeration of the services(gobuster is OP), finding vulnerabilites and exploiting it. In this case, we used a bit of OSINT to find the vulnerability by searching up the build number of the service and checking whether it is outdated and riddled with security flaws. Spend about 4 hours on this room 💀 and I did read a writeup for this room because I had no clue how to start. Going forward, I will attempt future CTFs with this methodology in mind.<br>

I also realised the attack sequence is quite similar to the allien dockerlabs machine that I did before this. The vulnerability is different (SMB), but it also does port scanning first, and then vulnerability discovery, username enumeration, password brute forcing, and then finally, a reverse shell code injection to get root access. P cool, much to learn still, like how exactly does reverse shell work?






