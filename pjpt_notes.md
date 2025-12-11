# Practical Junior Penetration Tester (PJPT) Certification

*Types of pentest assessments:*
- External Network Pentest.
  - Hacking in from the outside using Open Source Intelligence (OSINT).
  - Can be required for compliance.
  - Cheaper than larger scope assessments.
- Internal Network Pentest.
  - Heavy focus on AD attacks.
- Web Application Pentest.
  - Web-based attacks and Open Web Application Security Project (OWASP) guidelines.
  - OWASP top 10 attacks!
- Wireless Network Pentest.
  - Method depends on the type of network.
  - Straightforward. Use wireless network adapter.
  - Use packet injection.
- Physical Pentest & Social Engineering.
  - Method depends on the task and goals.
  - Phishing campaign.
- Mobile Penetration Testing.
- IoT Penetration Testing.
- Red Team Engagements.
- Purple Team Engagements.
- Etc...

*Report Writing:*
- Typically delivered within a week after the engagement.
- Highlight technical and non-technical findings.
- Recommendations for remediation.

*Debrief:*
- Walking through report findings, both technical and non-technical.
- Opportunity for the client to ask questions and express concerns.
- Finalize report after the debrief.

## Networking


### IP Addresses
Mainly communicate over Layer 3 (Router).<br>
IPv4 32 bit<br>
IPv6 128 bit

### MAC Addresses
MAC Address is in Layer 2, related to switching.<br>
First 3 pairs in MAC address are idenifiers.

### TCP & UDP
Layer 4.<br>
Transmission Control Protocol (TCP), very reliable. Connection.
- HTTP(S)
- SSH
- RDP
- SYN -> SYN ACK -> ACK *(Three way handshake)*
  
User Datagram Protocol (UDP), less reliable but fast. No connection.
- Media streeaming

### Common ports and protocols
TCP:
- FTP (21)
- SSH (22)
- Telnet (23)
- SMTP (25)
- DNS (53)
- HTTP/HTTPS (80/443)
- POP3 (110)
- SMB (139 & 445)
- IMAP (143)

UDP:
- DNS (53)
- DHCP (67 & 68)
- TFTP (69)
- SNMP (161)

### OSI-Model
Layer 1 - Physical, *cables*<br>
Layer 2 - Data, *switching, MAC addresses*<br>
Layer 3 - Network, *routing, IP addresses*<br>
Layer 4 - Transport, *TCP & UDP*<br>
Layer 5 - Session, *session management*<br>
Layer 6 - Presentation, *JPEG, MOV, etc...*<br>
Layer 7 - Application, *HTTP, SMB, FTP, etc...*

### Subnetting
netmask gives subnet.<br>
255.255.255.0 is common /24 network.<br>
11111111.11111111.11111111.00000000<br>
x = #flipped on bits,  /x network.<br>
**Just consider the binary representation for each octet.**

Network ID - First Address<br>
Broadcast IP - Last Address<br>

## The Five Stages of Ethical Hacking

### Reconnaissance

Passive:
- Looking for information on the internet.

Active:
- Use tools

### Scanning & Enumeration

Nmap, Nessus Nikto, etc.

Enumeration:
- Looking for value in found items.
- E.g. looking for outdated things running on an open port.

### Exploitation

Running an exploit to try to gain access using what was found in the previous phase.

### Maintain Access

Repeat the previous process and make sure you keep the access you have

### Covering Tracks

Remove all uploaded malware and clean up on every action you took.

## Information Gathering (Reconnaissance [Passive])

Good source for sources: https://osintframework.com/

### Passive Reconnaissance

Physical/Social:
- Location info
  - Satellite images
  - Drone recon
  - Building layout (blueprints)
- Job Information:
  - Employees (name, title, phone number, manager, ...)
  - Pictures (badge photos, desk photos, computer photos, ...)

Web/Host:
- Target Validation
- Finding Subdomains
- Fingerprinting
- Data Breaches

### Identifying our target

bugcrowd.com

### Discovering Email Addresses (E-Mail OSINT)

Looking for contact information online.
- hunter.io
  - Find patterns in e-mail address structure.
  - Select departments
- Phonebook.cz
  - Get e-mail from URL
  - Also domains and urls from URL.
- voilanorbert.com
  - Same as hunter.io
- Clearbit (Only in chrome)
  - Finds people
  - Sort by role
  - Sort by seniority

Verifying e-mail addresses.
- tools.verifyemailaddress.io (email hippo)
- email-checker.net/validate

Use "forgot password" to find more data (possibly other e-mails)

Steps:
- Google
- hunter.io/Phonebook.cz/Clearbit
- Verify

Use found data to password spray.

### Gathering breached credentials with Breach-Parse (Password OSINT)

github.com/hmaverickadams -> breach-parse (not required to install, useful tool!)

Alternate capitals when you observe patterns for credential stuffing.

### Hunting breached credentials with DeHashed (Password OSINT)

dehashed.com
- Search by known intel, eg. e-mail addresses, username, password, ...

hashes.org
- Search hashes

### Hunting subdomains

Use tools to find different subdomains (that maybe shouldn't be available).

sublist3r (install on kali!!!)
- Looks through searchengines to find subdomains

crt.sh (website)
- Uses certificate fingerprinting

Other tools for kali:
- owasp amass
- tomnomnom httprobe

### Identifying website technologies

You may be able to exploit vulnerabilities in the tech that is being ran.

builtwith.com
- Lookup websites and looks at what tech is running, eg. frameworks

wappalyzer (firefox extension install on kali!!!)
- Go to website and get an indication

whatweb
- Command in kali terminal
- Give a url and find the tech that the website uses and gives headers

### Information gathering with BurpSuite

Built into kali

BurpSuite is a web-proxy, meaning it intercepts traffic.

Set up firefox to utilize BurpSuite.
- Go to https://burp and click CA Certificate.
- Add certificate to firefox.

You can modify traffic in BurpSuite

In the target you can find all different traffic.
- Clicking on the website gives you more information on what's on the page
- Possibly server names, etc.

### Utilizing social media

Images are useful
- linkedin
- twitter
- instagram

Use earlier gleaned formatting to possibly determine e-mails.

Then password spray using weak passwords against these e-mails.

## Information Gathering (Reconnaissance [Active])

### Scanning with nmap

Use netdiscover to find other ip's on network.
- netdiscover -r xxx.xxx.xxx.0/24

nmap:
- nmap -sS (Stealth scanning [not actually stealthy])
- SYN SYNACK RST
- nmap -T4 -p- -A
  - -T4: Speed between 1-5, 4 is a choice
  - -p-: Scan all ports
    - Removing scans top 1000 ports.
    - -p 80,443,53: Scan specific port range
  - -A: Everything, all data you can find
- Host discovery
  - -sn
  - -pN
- Scan techniques
  - -sS
  - -sU (UDP scan)
- -sV: Spen ports for service info
- -sC: Script scanning
- -O: OS detection

First finding open ports, then getting intel on them is generally a good idea for speed.

### Enumeration HTTP/HTTPS

Attacking SMB and HTTP/HTTPS is usually a good first step.

Visit webpage if port 80 (HTTP) or port 443 (HTTPS) is exposed.

nikto:
- Web vulnerbility scanner
- Can be frequently autoblocked by websites
- nikto -h xxx.xxx.xxx.xxx
  - -h: host

dirbuster/dirb/gobuster for directory busting

dirbuster:
- Enter url: http://xxx.xxx.xxx.xxx:80/
- Choose list: /usr/share/dirbuster/...
- Enter file extension: php,txt,zip,pdf

burpsuite:
- Repeater to find response in realtime and modify your requests.

View sourcecode