FROM ubuntu:20.04

# Install openssh-client so we have ssh-keygen.
RUN apt update -qq && apt install -y -q openssh-client build-essential autoconf libz-dev git
RUN useradd -m -s /bin/bash ssh-mitm && \
    mkdir -p /home/ssh-mitm/bin /home/ssh-mitm/etc /home/ssh-mitm/log && \
    chown -R ssh-mitm:ssh-mitm /home/ssh-mitm/

COPY openssh-7.5p1 /home/ssh-mitm/openssh-7.5p1/

RUN git clone --depth 1 -b OpenSSL_1_0_2-stable https://github.com/openssl/openssl OpenSSL_1_0_2 && \
    cd OpenSSL_1_0_2 && ./config -v -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIC no-shared enable-weak-ssl-ciphers zlib && \
    make -j 1 depend && make -j 1 all


RUN cd /home/ssh-mitm/openssh-7.5p1 && \
     autoconf && \
    ./configure --with-sandbox=no --with-privsep-user=ssh-mitm --with-privsep-path=/home/ssh-mitm/empty --with-pid-dir=/home/ssh-mitm --with-lastlog=/home/ssh-mitm --with-ssl-dir=/OpenSSL_1_0_2 && \
    make -j 1

RUN ln -s /home/ssh-mitm/openssh-7.5p1/sshd /home/ssh-mitm/bin/sshd_mitm && \
    ln -s /home/ssh-mitm/openssh-7.5p1/ssh /home/ssh-mitm/bin/ssh && \
    cp /home/ssh-mitm/openssh-7.5p1/sshd_config /home/ssh-mitm/etc/sshd_config


USER ssh-mitm
WORKDIR /home/ssh-mitm
RUN mkdir -m 0700 /home/ssh-mitm/empty
RUN mkdir -m 0700 /home/ssh-mitm/.ssh
RUN mkdir -m 0700 /home/ssh-mitm/tmp

EXPOSE 2222/tcp

# This is ugly, but its the only thing I found which works.  This generates a new ED25519 & RSA host key each time the container is run.
CMD /usr/bin/ssh-keygen -q -t rsa -b 4096 -f /home/ssh-mitm/etc/ssh_host_rsa_key -N ''; /usr/bin/ssh-keygen -q -t ed25519 -f /home/ssh-mitm/etc/ssh_host_ed25519_key -N ''; /home/ssh-mitm/bin/sshd_mitm -D -f /home/ssh-mitm/etc/sshd_config
