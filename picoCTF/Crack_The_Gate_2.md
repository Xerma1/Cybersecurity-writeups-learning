# Crack The Gate 2

![img](https://i.pinimg.com/736x/72/93/36/729336f0868dc21313f73d2f0ca88d49.jpg)<br>

We are given the website, and a list of passwords:
```
FvQqRDID
o28yxJnz
dzXLq6iI
gQwoROCU
TqdQCjNn
VJSDcyso
wCLZCkww
GxjOadW5
3pcv6C7j
F0v4Jsmr
y9JoEDYm
QKCdmMKy
fnW92UyB
eMy1d5JZ
eturI0N3
pBT4eP6k
o1QeNZ3M
hdd1CWXH
R6flYmhD
cRdawYlr
```
Attempting to login after a failed attempt will block me from trying for the next 20 minutes. While I could realistically wait between each login in this challenge (since there are only so many passwords), in a real password brute-forcing attack, iterating through millions of passwords is gonna take decades.

## Method: Bypassing rate limitation via IP rotation

Use the `X-Forwarded-For` header. More details: https://www.typeerror.org/docs/http/headers/x-forwarded-for<br>

I used BurpSuite to intercept the POST request when I attempt to login, and sent the request to the Repeater. There, I added the header `X-Forwarded-For: 192.168.1.1` and changed the last byte of the IPv4 address whenever I want to test another password (IP rotation). So to the web server, it seems like a different user is trying to log in every time, when really it is all me. Rate limiting bypassed!<br>

Iterating through the password list, I finally hit one that works: `QKCdmMKy`. And in the response, I got the flag!<br>

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 132
ETag: W/"84-pibc6tcXvQX3j0gzj5k7R+NjjhE"
Date: Sun, 15 Mar 2026 11:26:56 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{
  "success":true,
  "email":"ctf-player@picoctf.org",
  "firstName":"pico",
  "lastName":"player",
  "flag":"picoCTF{xff_byp4ss_brut3_44b93275}"
}
```


