![img](https://github.com/Xerma1/Cybersecurity-writeups-learning/blob/b4ed7fa6bd2f724fe74119c40662eab25f87c078/assets/image.png)

# What is RSA??
RSA (Rivest - Shamir - Adleman) is a modern cryptography method that ensures encrypted end-to-end communication.<br>

It is an asymmetric encryption algorithm: It produces a public and private key. The public key is shared to everyone and is used to encrypt the message before sending it over to you. Only you can decrypt the message with your private key.

## How it works
The idea is that it is easy to multiply two massive prime numbers together to create a new number, but it is astronomically difficult to do reverse factoring to find out the two prime numbers that make up that number.<br>

- Pick two massive prime numbers, p and q
- Multiply them to form a new number, n, which is part of the public key (you will be sharing the number n).
- Find the Totient ($\phi$): $\phi(n) = (p-1) \times (q-1)$
- Choose an exponent ($e$): Usually a small prime like 65,537.
- Calculate the Private Key ($d$): This is the "modular inverse" of $e$. Basically, the number that satisfies $(d \times e) \pmod{\phi(n)} = 1$.

### Encryption
To send a message (m), the sender calculates:<br>
### $$c = m^e \pmod{n}$$
c is the encrypted message to be sent to the receiver.

### Decryption
To decrypt the message, the recipient will calculate:
### $$m = c^d \pmod{n}$$
m is the original message 

# The Challenge Room
The challenge gives us these values:
```
N: 20571289975934107508479318092429416684087924784525860765631277624896560389939207994147322121202730337382571445581714540889539964702171310946492778325331326
e: 65537
cyphertext: 452335188502528716344059968590011218506502374892404119198529625148062057875771477204959565536403027908495731393871729570965210183889722347553130631110603
```
We are also given the python code for the RSA encryption:
```
from sys import exit
from Crypto.Util.number import bytes_to_long, inverse
from setup import get_primes

e = 65537

def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p,q = get_primes(k//2)
    N = p*q
    d = inverse(e, (p-1)*(q-1))

    return ((N,e), d)

def encrypt(pubkey, m):
    N,e = pubkey
    return pow(bytes_to_long(m.encode('utf-8')), e, N)

def main(flag):
    pubkey, _privkey = gen_key(1024)
    encrypted = encrypt(pubkey, flag) 
    return (pubkey[0], encrypted)

if __name__ == "__main__":
    flag = open('flag.txt', 'r').read()
    flag = flag.strip()
    N, cypher  = main(flag)
    print("N:", N)
    print("e:", e)
    print("cyphertext:", cypher)
    exit()
```
The hint mentioned to "Try comparing N across multiple requests". So I am assuming that two pairs of N values share something in common, probably one of the prime pairs is the same.<br>

So I got 2 N values, find the GCD for the 2 values, which is `2`. This proves that their p value is 2.<br>

With the value of p discovered, I can easily unravel the entire RSA encryption by finding the q, the totient, and then the private key. Using the private key, I can decode the message and fetch the hidden flag.
```
import math
from Crypto.Util.number import inverse, long_to_bytes

# Get all primes in a range
e = 65537
c = 12081554619181551709584168530077165721351309976285597741327195617038288707039839820186698070847425577234969096003399635790461244204117633244881333153328219

n1 = 16259160251520897603017852151870826946974462765178479936467764990217901782369143461596378862691549384932862034485134803791977030664727039170974467993066538
n2 = 15567687510516372807072853159317282931252960148231660223847090966630611875942810438568402898238105536951920573936067485565333803816459173738676031238077414

p = math.gcd(n1, n2)
q = n2 // p
totient = (p - 1) * (q - 1)
d = pow(e, -1, totient)
m = pow(c, d, n2)

m = long_to_bytes(m)
message_bytes = m.decode('utf-8')

print(message_bytes)
```
Flag: `picoCTF{tw0_1$_pr!m375129bb1}`

# Lesson
- In RSA encryption, don't use small p and q values, and do not reuse p or q values.



