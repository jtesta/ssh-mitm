FROM ubuntu:20.04

# Install openssh-client so we have ssh-keygen.
RUN apt update -qq && apt install -y -q openssh-client
RUN useradd -m -s /bin/bash ssh-mitm

COPY openssh-7.5p1-mitm/sshd /home/ssh-mitm/bin/sshd_mitm
COPY openssh-7.5p1-mitm/ssh /home/ssh-mitm/bin/ssh
COPY openssh-7.5p1-mitm/ssh_config.mitm /home/ssh-mitm/etc/ssh_config
COPY openssh-7.5p1-mitm/sshd_config /home/ssh-mitm/etc/sshd_config
RUN chown ssh-mitm:ssh-mitm /home/ssh-mitm/etc/

USER ssh-mitm
WORKDIR /home/ssh-mitm
RUN mkdir -m 0700 /home/ssh-mitm/empty /home/ssh-mitm/.ssh /home/ssh-mitm/tmp

EXPOSE 2222/tcp

# This is ugly, but its the only thing I found which works.  This generates a new ED25519 & RSA host key each time the container is run.
CMD /usr/bin/ssh-keygen -t rsa -b 4096 -f /home/ssh-mitm/etc/ssh_host_rsa_key -N ''; /usr/bin/ssh-keygen -t ed25519 -f /home/ssh-mitm/etc/ssh_host_ed25519_key -N ''; echo; /home/ssh-mitm/bin/sshd_mitm -D -f /home/ssh-mitm/etc/sshd_config
