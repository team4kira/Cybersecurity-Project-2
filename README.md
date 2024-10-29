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
| Remediation | *	Encrypt Sensitive Information. (T1659) *	Restrict Web-Based Content. (T1659) *	Input Validation. (Stone, Verizon) *	Data Sanitization. (Stone, Verizon) *	Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) |

| Vulnerability 2 | Findings |
| --- | --- |
| Title  | XSS Stored |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Medium |
| Description | In LOM’s assessment of the ‘comments.php’ pages, it was found that a XSS stored injection could be created. The lack of data sanitization and input validation in the web applications allowed LOM to send malicious XSS stored code onto this web page. Upon refreshment, the code was still within the page source, leaving a vulnerability that can affect any future visitors to the site. |
| Images |  |
| Affected Hosts | 192.168.14.35/comments.php |
| Remediation | •	Encrypt Sensitive Information (T1659) •	Restrict Web-Based Content (T1659) •	Input Validation. (Stone, Verizon) •	Data Sanitization. (Stone, Verizon) •	Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) |

| Vulnerability 3 | Findings |
| --- | --- |
| Title  | Local File Injection |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | High |
| Description | A basic PHP script file was uploaded by LOM. This revealed that the web page was configured to accept various file types, not just image files. Some security measures were in place, as it looked for image keywords like the file type ‘.jpg.’ However, if you added just ‘.jpg’ within the file description, it allowed a malicious payload to be uploaded, in this case, a .php file. |
| Images |  |
| Affected Hosts | 192.168.13.45/Memory-Planner.php |
| Remediation | •	Remove file inclusion input if possible. •	Create a whitelist of files that may be included on the web page. (OWASP, WSTG – v4.1) |

| Vulnerability 4 | Findings |
| --- | --- |
| Title  | SQL Injection |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Critical |
| Description | In the evaluation of the Login.php webpage, it was found that SQL injection attacks were permissible. The following injection was utilized: ‘ or 1=1#. This resulted in the retrieval of flags and additional data that could be utilized for further exploitations. |
| Images |  |
| Affected Hosts | 192.168.13.45/Login.php |
| Remediation | •	Encrypt Sensitive Information (T1659) <br> •	Restrict Web-Based Content (T1659) <br> •	Input Validation. (Stone, Verizon) <br> •	Utilization of Prepared Statements. (OWASP, SQL Injection Prevention Cheat Sheet) |
