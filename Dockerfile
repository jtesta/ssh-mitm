FROM ubuntu:20.04 as builder

# Install openssh-client so we get ssh-keygen.
RUN apt update -qq && apt install -y -q openssh-client


# Copy ssh-keygen (and library dependency) to our final image.
FROM ubuntu:20.04
COPY --from=builder /lib/x86_64-linux-gnu/libcrypto.so.1.1 /lib/x86_64-linux-gnu/libcrypto.so.1.1
COPY --from=builder /usr/bin/ssh-keygen /usr/bin/ssh-keygen

RUN useradd -m -s /bin/bash ssh-mitm

COPY openssh-7.5p1-mitm/sshd /home/ssh-mitm/bin/sshd_mitm
COPY openssh-7.5p1-mitm/ssh /home/ssh-mitm/bin/ssh
COPY openssh-7.5p1-mitm/ssh_config.mitm /home/ssh-mitm/etc/ssh_config
COPY openssh-7.5p1-mitm/sshd_config /home/ssh-mitm/etc/sshd_config
RUN chown ssh-mitm:ssh-mitm /home/ssh-mitm/etc/

USER ssh-mitm
WORKDIR /home/ssh-mitm
RUN mkdir -m 0700 /home/ssh-mitm/empty /home/ssh-mitm/.ssh /home/ssh-mitm/tmp /home/ssh-mitm/log

COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 2222/tcp

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD /home/ssh-mitm/bin/sshd_mitm -D -f /home/ssh-mitm/etc/sshd_config
