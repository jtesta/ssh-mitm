all:
	./install.sh

clean:
	test -f openssh-7.5p1-mitm/Makefile && $(MAKE) -C openssh-7.5p1-mitm clean || echo "OpenSSH directory is already clean."
	$(MAKE) -C openssl-1.0.2u clean
