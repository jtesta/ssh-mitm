#!/bin/bash

if [ ! -f /home/ssh-mitm/etc/ssh_host_rsa_key ]; then
    echo -e "\nSSH host keys not found.  Generating new ones...\n"
    /usr/bin/ssh-keygen -t rsa -b 4096 -f /home/ssh-mitm/etc/ssh_host_rsa_key -N ''
    /usr/bin/ssh-keygen -t ed25519 -f /home/ssh-mitm/etc/ssh_host_ed25519_key -N ''
    echo
else
    echo -e "\nExisting SSH host keys found:\n"
    /usr/bin/ssh-keygen -lf /home/ssh-mitm/etc/ssh_host_rsa_key
    /usr/bin/ssh-keygen -lf /home/ssh-mitm/etc/ssh_host_ed25519_key
fi

# start default cmd
exec "$@"
