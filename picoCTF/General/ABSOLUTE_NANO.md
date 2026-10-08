## ABSOLUTE NANO
```
You have complete power with nano.

Think you can get the flag?
```

The challenge presents us with an ssh to the challenge machine. Once in, we type `ls` to view the directory:
```
flag.txt
```
Trying to simply `cat flag.txt` presents a `cat: flag.txt: Permission denied` error. `ls -l` shows that I do not have read access:
```
total 4
-r--r----- 1 root root 35 Sep 23 06:56 flag.txt
```
Inferring from the challenge title, it seems that we can gain elevated privileges from nano somehow. After a little research, I found out that I can run commands in nano with `ctrl + R`  and `ctrl + X`. <br>

To see what root-level privileges I am given access to, I run `sudo -l`:
```
Matching Defaults entries for ctf-player on challenge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User ctf-player may run the following commands on challenge:
    (ALL) NOPASSWD: /bin/nano /etc/sudoers
```

Oh my, looks like I can use nano to read `/etc/sudoers` without a password! So I happily typed in `sudo nano /etc/sudoers` to run nano with elevated privileges. 

Then I ran the command `cat flag.txt` to receive the flag appended to the bottom of the file.

# Lessons learnt
Even if you deny read access to unprivileged users, granting then privilege access to a file editor, even for an unrelated file, can allow them to escalate their privileges. Be careful of what `sudo` access you grant to users! 

