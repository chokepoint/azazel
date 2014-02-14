##Azazel
####V 0.1
---
Azazel is a userland rootkit based off of the original LD_PRELOAD technique from Jynx rootkit.  It is more robust and has additional features, and focuses heavily around anti-debugging and anti-detection.

###Features
* Anti-debugging
* Avoids unhide, lsof, ps, ldd detection
* Hides files and directories
* Hides remote connections
* Hides processes
* Hides logins
* PCAP hooks avoids local sniffing
* Two accept backdoors.
 * [Crypthook](https://github.com/chokepoint/CryptHook) encrypted accept() backdoor -- Full PTY
 * Plaintext accept() backdoor           -- Full PTY
* PAM backdoor for local privesc and remote entry
* Log cleanup for utmp/wtmp entries based on pty

### Links
* [Documentation](http://www.blackhatlibrary.net)
* [Chokepoint](http://www.chokepoint.net)
