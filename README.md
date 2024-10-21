# Cybersecurity-Project-2: Exploit Vulnerabilities in Rekall Corporation's Web Application, Linux Servers, and Windows Servers
For this cybersecurity project, I created a hypothetical company named L'Ordinateur de la Maison (LOM). LOM was authorized by the fictional Rekall Corporation to conduct a vulnerability assessment of Rekall's web application, Linux machine, and Windows machine. Below shows my vulnerability findings for the project. 

By: Kevin D

| Vulnerabilities | Severity |
| --- | --- |
| XSS Reflected  | Medium |
| XSS Stored | Medium |
| Local File Injection | High |
| SQL Injection | Critical |
| Weak Password on Web Application | Critical |
| Command Injection | Medium |
| PHP Injection | Critical |
| Brute Force Attack | Medium |
| Directory Traversal | Medium |
| Apache Tomcat Remote Code Execution Vulnerability | High |
| Shellshock | Critical |
| Struts | High |
| Drupal | High |
| Password Guessing in SSH | Critical |
| Sudo Command Privilege Vulnerability | Critical |
| FTP Anonymous Vulnerability | High |
| Slmail Vulnerability | Critical |
| LSAdump Attack | High |
| WMI Vulnerability | Critical |
| DCSync Attack | Critical |

| Vulnerability 1 | Findings |
| --- | --- |
| Title  | XSS Reflected |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Medium |
| Description | In LOM’s assessment, the ‘Welcome.php’ and the ‘Memory-Planner.php’ pages were evaluated. Utilizing an XSS reflected injection, flags within the web applications were uncovered. The lack of data sanitization and input validation in the web applications allowed LOM to send a malicious XSS reflected code on these two web pages |
| Images |  |
| Affected Hosts | 192.168.14.35/Memory-Planner.php & 192.168.14.35/Welcome.php |
| Remediation | *	Encrypt Sensitive Information. (T1659)
*	Restrict Web-Based Content. (T1659)
*	Input Validation. (Stone, Verizon)
*	Data Sanitization. (Stone, Verizon)
*	Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) |
