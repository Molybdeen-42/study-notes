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
- Looking for information on the internet.'

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