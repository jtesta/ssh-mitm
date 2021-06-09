#!/bin/bash

if [ ! -f /home/ssh-mitm/etc/ssh_host_rsa_key ]; then
    /usr/bin/ssh-keygen -q -t rsa -b 4096 -f /home/ssh-mitm/etc/ssh_host_rsa_key -N ''
    /usr/bin/ssh-keygen -q -t ed25519 -f /home/ssh-mitm/etc/ssh_host_ed25519_key -N ''
fi

# start default cmd
exec "$@"
