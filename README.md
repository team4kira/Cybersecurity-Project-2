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
| Images | ![Local Image](Screenshots/V1.jpg) |
| Affected Hosts | 192.168.14.35/Memory-Planner.php & 192.168.14.35/Welcome.php |
| Remediation | •	Encrypt Sensitive Information. (T1659) <br> •	Restrict Web-Based Content. (T1659) <br> •	Input Validation. (Stone, Verizon) <br> •	Data Sanitization. (Stone, Verizon) <br> •	Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) |

| Vulnerability 2 | Findings |
| --- | --- |
| Title  | XSS Stored |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Medium |
| Description | In LOM’s assessment of the ‘comments.php’ pages, it was found that a XSS stored injection could be created. The lack of data sanitization and input validation in the web applications allowed LOM to send malicious XSS stored code onto this web page. Upon refreshment, the code was still within the page source, leaving a vulnerability that can affect any future visitors to the site. |
| Images | ![Local Image](Screenshots/V2.jpg) |
| Affected Hosts | 192.168.14.35/comments.php |
| Remediation | •	Encrypt Sensitive Information. (T1659) <br> •	Restrict Web-Based Content. (T1659) <br> •	Input Validation. (Stone, Verizon) <br> •	Data Sanitization (Stone, Verizon) <br> •	Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) |

| Vulnerability 3 | Findings |
| --- | --- |
| Title  | Local File Injection |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | High |
| Description | A basic PHP script file was uploaded by LOM. This revealed that the web page was configured to accept various file types, not just image files. Some security measures were in place, as it looked for image keywords like the file type ‘.jpg.’ However, if you added just ‘.jpg’ within the file description, it allowed a malicious payload to be uploaded, in this case, a .php file. |
| Images | ![Local Image](Screenshots/V3.jpg) |
| Affected Hosts | 192.168.13.45/Memory-Planner.php |
| Remediation | •	Remove file inclusion input if possible. <br> •	Create a whitelist of files that may be included on the web page. (OWASP, WSTG – v4.1) |

| Vulnerability 4 | Findings |
| --- | --- |
| Title  | SQL Injection |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Critical |
| Description | In the evaluation of the Login.php webpage, it was found that SQL injection attacks were permissible. The following injection was utilized: ‘ or 1=1#. This resulted in the retrieval of flags and additional data that could be utilized for further exploitations. |
| Images | ![Local Image](Screenshots/V4.jpg) |
| Affected Hosts | 192.168.13.45/Login.php |
| Remediation | •	Encrypt Sensitive Information. (T1659) <br> •	Restrict Web-Based Content. (T1659) <br> •	Input Validation. (Stone, Verizon) <br> •	Utilization of Prepared Statements. (OWASP, SQL Injection Prevention Cheat Sheet) |

| Vulnerability 5 | Findings |
| --- | --- |
| Title  | Weak Password on Web Application |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Critical |
| Description | The host 192.168.13.45/Login.php contains a hidden username and password that can be identified by inspecting the web page's source code or by selecting the field after 'Login' and 'Password.' The password itself is also not secure, as both the username and password relate to the film Total Recall, making it easily guessable, even if not plainly visible. |
| Images | ![Local Image](Screenshots/V5.jpg) |
| Affected Hosts | 192.168.13.45/Login.php |
| Remediation | •	Account Lockout policy should be created to lock individuals out after a certain number of failed login attempts. (T1110.003) <br> •	Enable the use of multi-factor authentication. (T1110.003) <br> •	Use administrative controls to train staff on Password Policies. Use NIST as a password policy guide. (T1110.003) <br> •	Reset compromised passwords and make sure it is not affiliated with the username. <br> |

| Vulnerability 6 | Findings |
| --- | --- |
| Title  | Command Injection |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Medium |
| Description | In the evaluation of the networking.php page, command injection vulnerabilities were discovered, allowing access to various directories and files within the web application. This vulnerability has the potential to provide additional data, enabling further exploitation of resources at later times. |
| Images | ![Local Image](Screenshots/V6.jpg) |
| Affected Hosts | 192.168.13.45/networking.php |
| Remediation | •	Encrypt Sensitive Information. (T1659) <br> •	Restrict Web-Based Content. (T1659) <br> •	Input Validation. (Stone, Verizon) <br> •	Data Sanitization. (Stone, Verizon) <br> •	Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) |

| Vulnerability 7 | Findings |
| --- | --- |
| Title  | PHP Injection |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Critical |
| Description | The following PHP injection was employed by LOM to retrieve credential details from the host 192.168.14.35: 'php?message=passthru(whoami)'. The result returned was www-data is the user account. This indicated that the site was vulnerable to various types of PHP code injection, as parameters like the eval() function were not restricted. If left unaddressed, this vulnerability could result in further exploitation. |
| Images | ![Local Image](Screenshots/V7.jpg) |
| Affected Hosts | 192.168.13.35 |
| Remediation | • Data Sanitization. (Stone, Verizon) <br> • Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) <br> • Disable Eval to prohibit arbitrary code from being executed. (Moradov, Bright) <br> • Keep PHP updated with the latest security patches. <br> • Utilize a Web Application Firewall to filter HTTP requests that may have suspicious patterns. |

| Vulnerability 8 | Findings |
| --- | --- |
| Title  | Bute Force Attack |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Medium |
| Description | By utilizing Burp Suite and the Firefox addon Foxy Proxy, LOM identified the username and password to the host 192.168.13.45. This enabled further identification of usernames and passwords that could potentially be exploited on the web application. This shows that the site does not have adequate password policies, as evidenced by the numerous failed attempts that were permitted during execution. |
| Images | ![Local Image](Screenshots/V8.jpg) |
| Affected Hosts | 192.168.13.45/Login.php |
| Remediation | •	Account Lockout policy should be created to lock individuals out after a certain number of failed login attempts. (T1110.003) <br> •	Enable the use of multi-factor authentication. (T1110.003) <br> •	Use administrative controls to train staff on Password Policies. Use NIST as a password policy guide. (T1110.003) <br> •	Reset compromised passwords. |

| Vulnerability 9 | Findings |
| --- | --- |
| Title  | Directory Traversal |
| Type (Web app / Linux OS / Windows OS)  | Web Application |
| Risk Rating | Medium |
| Description | Using prior vulnerabilities discovered in the old_disclaimer directory of the Web Application, LOM successfully employed a path traversal technique on the disclaimer.php page. The following directory traversal command was inputted to show the data from the file: '192.168.13.35/disclaimer.php?page=old_disclaimers/disclaimer_1.txt'. This allowed for the identification of disclaimer text files containing valuable information and flags. |
| Images | ![Local Image](Screenshots/V9.jpg) |
| Affected Hosts | 192.168.13.35/disclaimer.php |
| Remediation | •	Adjust file privileges to ensure only authorized users are able to see files and directories. <br> •	Data Sanitization. (Stone, Verizon) <br> •	Utilize Web Application Firewall rules to block abnormal requests. (Stone, Verizon) |

| Vulnerability 10 | Findings |
| --- | --- |
| Title  | Apache Tomcat Remote Code Execution Vulnerability |
| Type (Web app / Linux OS / Windows OS)  | Linux OS |
| Risk Rating | High |
| Description | The multi/http/tomcat_jsp_upload_bypass Metasploit module was utilized by LOM to demonstrate the Apache Remote Code Execution vulnerability. This Metasploit module utilizes a PUT request to facilitate the upload of a JSP shell (Rapid7, Tomcat RCE). By configuring the remote host IP address to 192.138.13.10, a meterpreter shell was generated by LOM, granting access to the Linux operating system. |
| Images | ![Local Image](Screenshots/V10.jpg) |
| Affected Hosts | 192.168.13.10:80 |
| Remediation | •	Update Apache Tomcat. <br> •	Remove the ROOT Folder if possible as the vulnerability is limited to the ROOT web application of Apache Tomcat. (Nist, CVE-2023-41080) |

| Vulnerability 11 | Findings |
| --- | --- |
| Title  | Shellshock |
| Type (Web app / Linux OS / Windows OS)  | Linux OS |
| Risk Rating | Critical |
| Description | The Metasploit module exploit/multi/http/apache_mod_cgi_bash_env_exec was executed by LOM. The following options were configured: remote host: 192.168.13.11. This Shellshock vulnerability exploits a flaw in the Bash shell by targeting CGI scripts in the Apache web server, manipulating the HTTP_USER_AGENT to enable malicious activities (Rapid7, Apache mod_cgi). This exploit granted root access, allowing for the reconfiguration of etc/sudoers, which in turn could be used to modify privileges on the Linux OS. |
| Images | ![Local Image](Screenshots/V11.jpg) |
| Affected Hosts | 192.168.13.11 |
| Remediation | •	Update to the latest version of BASH. <br> •	Create a mod_security_rule that would reject HTTP request containing data that may be interpreted by Bash. (RedHat, Mitgating the Shellshock) <br> •	Use IPTable rules to drop unwanted packets. (RedHat, Mitgating the Shellshock) |

| Vulnerability 12 | Findings |
| --- | --- |
| Title  | Struts |
| Type (Web app / Linux OS / Windows OS)  | Linux OS |
| Risk Rating | High |
| Description | Utilizing Nessus for reconnaissance, LOM identified a Struts exploitation in the host 192.168.13.12. With this knowledge, the metasploit module multi/http/struts2_content_type_ognl was deployed on the aforementioned host. This module exploits a remote code execution vulnerability in Apache versions 2.3.5 – 2.3.31 and 2.5 – 2.5.10 (Rapid7, Apache Struts). This enabled LOM to establish a meterpreter session and gain access to the root directory of the Linux OS. |
| Images | ![Local Image](Screenshots/V12.jpg) |
| Affected Hosts | 192.168.13.12 |
| Remediation | •	Update Apache Struts. <br> •	Utilize a Web Application Firewall (WAF) on the backend application server. (Crosser, Praetorian) |

| Vulnerability 13 | Findings |
| --- | --- |
| Title  | Drupal  |
| Type (Web app / Linux OS / Windows OS)  | Linux OS |
| Risk Rating | High |
| Description | After identifying a Drupal vulnerability on host 192.168.13.13, LOM utilized the Metasploit module exploit unix/webapp/drupal_restws_unserialize to establish a meterpreter session. This was accomplished by specifying the aforementioned host and executing the module. Subsequently, LOM identified www-data as the UID of the host, which proved to be valuable post-reconnaissance information. |
| Images | ![Local Image](Screenshots/V13.jpg) |
| Affected Hosts | 192.168.13.13 |
| Remediation | •	Update Drupal to the latest version. <br> •	If possible, disable POST, PATCH and PUT. (Rapid7, Drupal RESTful) |

| Vulnerability 14 | Findings |
| --- | --- |
| Title  | Password Guessing |
| Type (Web app / Linux OS / Windows OS)  | Linux OS |
| Risk Rating | Critical |
| Description | Utilizing OSINT's domain dossier for reconnaissance, LOM identified an SSH Username of Alice. Subsequently, LOM initiated password guessing, and it was discovered that the admin in question used her name, ‘alice’, as the password. This made it easy to access the host 192.168.13.14. |
| Images | ![Local Image](Screenshots/V14.jpg) |
| Affected Hosts | 192.168.13.14 |
| Remediation | •	Account Lockout policy should be created to lock individuals out after a certain number of failed login attempts. (T1110.003) <br> •	Enable the use of multi-factor authentication. (T1110.003) <br> •	Use administrative controls to train staff on Password Policies. Use NIST as a password policy guide. (T1110.003) <br> •	Reset password to something longer and more secure. <br> •	Consider password encryptions. |

| Vulnerability 15 | Findings |
| --- | --- |
| Title  | Sudo Command Privileges Vulnerability |
| Type (Web app / Linux OS / Windows OS)  | Linux OS |
| Risk Rating | Critical |
| Description | Once access to the Linux OS was gained, LOM utilized a sudo privilege exploitation. This was achieved using the following command: 'sudo -u#-1'. This exploitation works due to a Runas ALL sudoer vulnerability, which can bypass policy blacklists, allowing sudo with crafted user IDs (Nist, CVE-2019-14287). This vulnerability provides full access to the affected host, including all of its files and directories. |
| Images | ![Local Image](Screenshots/V15.jpg) |
| Affected Hosts | 192.168.13.14 |
| Remediation | •	Ensure you have a sudo version that is NOT prior to 1.8.28. <br> •	Examine all sudoers that include ‘!’ character and ensure that root user is not among the exclusions. (Rhett, VulCan) |

| Vulnerability 16 | Findings |
| --- | --- |
| Title  | FTP Anonymous Vulnerability |
| Type (Web app / Linux OS / Windows OS)  | Windows OS |
| Risk Rating | High |
| Description | After performing a nmap scan: 'nmap -A 172.22.117.20', it was revealed that port 21/FTP was open on the Windows 10 Machine. From there, LOM exploited the anonymous FTP vulnerability by logging into FTP using an anonymous username. Anonymous FTP allows users to access FTP servers without providing a user ID (Awati, TechTarget). This leaves the aforementioned host vulnerable to further exploitation and post-reconnaissance attacks. |
| Images | ![Local Image](Screenshots/V16.jpg) |
| Affected Hosts | 172.22.117.20:21 |
| Remediation | •	Disable FTP on affected host. <br> •	If FTP cannot be disabled limit the anonymous user to downloading only, to prohibit malicious file uploads. (BU TechWeb) <br> •	Create a Cron job that monitors the FTP server. (BU TechWeb) |

| Vulnerability 17 | Findings |
| --- | --- |
| Title  | SLMail Vulnerability |
| Type (Web app / Linux OS / Windows OS)  | Windows OS |
| Risk Rating | Critical |
| Description | The previous nmap scan also revealed the SLMail service being open via POP3 protocol on port 110. With this data, LOM employed the Metasploit module windows/pop3/seattlelab_pass by specifying 172.22.117.20 as the Remote Host. This module operates by sending an excessively long password to trigger an unauthenticated buffer overflow in the POP3 server (Rapid7, Seattle Lab). This leads to a successful exploitation without crashing the service or server (ibid), resulting in a successful meterpreter session that provides access to the Windows Machine. |
| Images | ![Local Image](Screenshots/V17.jpg) |
| Affected Hosts | 172.22.117.20:110 |
| Remediation | •	Disable SLMail service if possible. <br> •	Update to the latest version of SLMail. |

| Vulnerability 18 | Findings |
| --- | --- |
| Title  | LSADUMP Attack |
| Type (Web app / Linux OS / Windows OS)  | Windows OS |
| Risk Rating | High |
| Description | The exploitation of LSADUMP enabled LOM to execute a credential dumping attack. After creating a meterpreter session via the window/pop3/seattlelab_pass Metasploit module (as detailed in the previous vulnerability), the tool Mimikatz was deployed. The following Mimikatz command was utilized: 'kiwi_cmd lsadump::cache'. This command facilitates the extraction of cached credentials from the Local Security Authority (LSA) (Hacker Too, cache), accomplished through enumeration from the Windows Registry (ibid). This allowed LOM to capture flags and user credentials. |
| Images | ![Local Image](Screenshots/V18.jpg) |
| Affected Hosts | 172.22.117.20 |
| Remediation | •	Enable LSA Protection on Windows (Einoryte, NordVPN) <br> •	Use anti-malware software as it can detect malware attacks including Minikatz. (Einoryte, NordVPN). |

Work Citation: 

Awati, R. Anonymous FTP (File Transfer Protocol). Tech Target. https://www.techtarget.com/whatis/definition/anonymous-FTP-File-Transfer-Protocol 

Bu TechWeb. (2024) Securing FTP Servers. BU Tech Web. https://www.bu.edu/tech/about/security-resources/bestpractice/ftp/ 

Crosser, A. (2023) Understanding the Impact of the new Apache Struts File Upload Vulnerability. Praetorian. https://www.praetorian.com/blog/cve-2023-50164-apache-struts-file-upload-vulnerability/ 

Einoryte, A. (2023) What is Mimikatz? What it can do, and how to protect yourself. NordVPN. NordVPN Link. 

Joyce, K. (2021) What is DCSync Attack? Netwrix. https://blog.netwrix.com/2021/11/30/what-is-dcsync-an-introduction/ 

Microsoft. (2024) Windows Management Instrumentation. Microsoft. https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page 

Mitre | Attack: 
-	T1003.006 (2021) (https://attack.mitre.org/techniques/T1003/006/)
-	T1047 (2024) (https://attack.mitre.org/techniques/T1047/)
-	T1110.003 (2024) (https://attack.mitre.org/techniques/T1110/003/)
-	T1659 (2023) (https://attack.mitre.org/techniques/T1659/)

Moradov, O. (2022) PHP Code Injection: Examples and 4 Prevention Tips. Bight. https://brightsec.com/blog/code-injection-php/ 

Nist. (2019) CVE-2019-14287 Detail. Nist. https://nvd.nist.gov/vuln/detail/CVE-2019-14287 

Nist. (2024) CVE-2023-41080 Detail. Nist. https://nvd.nist.gov/vuln/detail/CVE-2023-41080 

OWASP. (2024) SQL Injection Prevention Cheat Sheet. OWASP. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html 

OWASP. (2024) WSTF – v4.1 Testing for Local File Inclusion. OWASP. OWASP Link. 

Rapid7. (2018) Apache mod_cgi Bash Environment Vairable Code Injection (Shellshock). Rapid 7. https://www.rapid7.com/db/modules/exploit/multi/http/apache_mod_cgi_bash_env_exec/ 

Rapid7. (2018) Apache Struts Jakarta Multipart Parser OGNL Injection. Rapid 7. https://www.rapid7.com/db/modules/exploit/multi/http/struts2_content_type_ognl/ 

Rapid7. (2019) Drupal RESTful Web Services unserialize() RCE. Rapid 7. https://www.rapid7.com/db/modules/exploit/unix/webapp/drupal_restws_unserialize/ 

Rapid7. (2018) Seattle Lab Mail 5.5 POP3 Overflow. Rapid 7. https://www.rapid7.com/db/modules/exploit/windows/pop3/seattlelab_pass/ 

Rapid7. (2018) Tomcat RCE via JSP Upload Bypass. Rapid7. https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_jsp_upload_bypass/ 

Rapid7. (2018) Windows Management Instrumentation (WMI) Remote Command Execution. Rapid 7. https://www.rapid7.com/db/modules/exploit/windows/local/wmi/ 

Red Hat. (2014) Mitigating the Shellshock Vulnerability (CVE-2014-6721 and CVE-2014-7169). Red Hat. https://access.redhat.com/articles/1212303 

Rhett. (2019) CVE-2019-14287 is Out, But a Workaround’s Available. VulCan. https://vulcan.io/blog/cve-2019-14287-is-out-but-a-workarounds-available/ 

Stone, M. (2024) How to Mitigate Cross-Site Scripting. Verizon. https://www.verizon.com/business/resources/articles/s/how-to-mitigate-cross-site-scripting/ 

The Hacker Tools. (2024) Cache. The Hacker Tool. https://tools.thehacker.recipes/mimikatz/modules/lsadump/cache 

