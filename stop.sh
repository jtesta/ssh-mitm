#!/bin/bash

# stop.sh
# Copyright (C) 2017  Joe Testa <jtesta@positronsecurity.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms version 3 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [[ `id -u` != 0 ]]; then
    echo "Error: this script must be run as root."
    exit -1
fi

if [[ (! -f /home/ssh-mitm/run.sh) || (! -f /home/ssh-mitm/bin/sshd_mitm) ]]; then
    echo "Error: could not find sshd_mitm.  You need to first run install.sh."
    exit -1
fi

# Check if --force arg is present.
FORCE=0
if [[ ($# == 1) && ($1 == '--force') ]]; then
    FORCE=1
fi


# If arpspoof or ettercap are running, stop.  Disabling the forwarding
# configuration while still ARP spoofing would cause a denial of service...
ps ax | awk '{print $5}' | egrep 'arpspoof|ettercap' > /dev/null
if [[ ($? == 0) && ($FORCE != 1) ]]; then
   echo -e "It looks like arpspoof or ettercap is still running.  You need to stop it before running this script, otherwise you'll cause a denial-of-service for the ARP targets.\n\nOtherwise, if you know what you're doing, re-run this script with '--force'."
   exit -1
else
   echo "Forcing termination..."
fi

# Kill all processes belonging to the ssh-mitm user.
killall -u ssh-mitm 2> /dev/null

echo "Disabling IP forwarding in the kernel..."
echo 0 > /proc/sys/net/ipv4/ip_forward

# Check if the INPUT table has an ACCEPT for destination port 2222.  If so,
# delete it.
iptables -nL INPUT | egrep "ACCEPT +tcp +-- +0\.0\.0\.0/0 +0\.0\.0\.0/0 +tcp dpt:2222" > /dev/null
if [[ $? == 0 ]]; then
    echo "Executing: iptables -D INPUT -p tcp --dport 2222 -j ACCEPT"
    iptables -D INPUT -p tcp --dport 2222 -j ACCEPT
    if [[ $? != 0 ]]; then
        echo "ERROR: failed to remove iptables rule!"
        exit -1
    fi
fi

# Check if the PREROUTING table has a REDIRECT for port 22 to 2222.  If so,
# delete it.
iptables -t nat -nL PREROUTING | egrep "REDIRECT +tcp +-- +0\.0\.0\.0/0 +0\.0\.0\.0/0 +tcp dpt:22 redir ports 2222" > /dev/null
if [[ $? == 0 ]]; then
    echo "Executing: iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222"
    iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
    if [[ $? != 0 ]]; then
        echo "ERROR: failed to remove iptables rule!"
        exit -1
    fi
fi

echo -e "\nSuccessfully stopped sshd_mitm daemon and disabled forwarding rules.\n"
exit 0
