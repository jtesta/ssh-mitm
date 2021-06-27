#!/bin/bash

# install.sh
# Copyright (C) 2017-2021, Joe Testa <jtesta@positronsecurity.com>
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

openssh_source_dir='openssh-7.5p1-mitm'
openssl_source_dir='openssl-1.0.2u'

# Find the total number of CPU cores on this machine.
NUM_PROCS=4
if [[ -x /usr/bin/nproc ]]; then
    NUM_PROCS=`/usr/bin/nproc --all`
fi
echo "Detected ${NUM_PROCS} CPU cores."

# Terminal colors.
CLR="\033[0m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
REDB="\033[1;31m"    # Red + bold
YELLOWB="\033[1;33m" # Yellow + bold
GREENB="\033[1;32m"  # Green + bold
WHITEB="\033[1;37m"  # White + bold


# Resets the environment (in case this script was run once before).
function reset_env {

    # Make sure no sshd_mitm is running and the user is logged out.
    killall -u ssh-mitm 2> /dev/null

    # Check if the ssh-mitm user exists.
    id ssh-mitm > /dev/null 2> /dev/null
    if [[ $? == 0 ]]; then

	# The user exists.  If this script was run with the "--force" argument,
        # then we will delete the user.
        if [[ $1 == '--force' ]]; then
	    echo -e "\n${YELLOWB}Flag '--force' used; deleting ssh-mitm user...\n${CLR}"
            userdel -f -r ssh-mitm 2> /dev/null

        # There could be saved sessions from an old version of SSH MITM that
        # we shouldn't destroy automatically.
        else

	    # If Docker was previously configured, remove its config dir and re-create it.
	    if [[ -d /home/ssh-mitm/.docker ]]; then
		rm -rf /home/ssh-mitm/.docker
		mkdir -m 0700 -p /home/ssh-mitm/.docker/run
		chown -R ssh-mitm:ssh-mitm /home/ssh-mitm/.docker
	    fi

            echo -e "${YELLOWB}It appears that the ssh-mitm user already exists.${CLR}  Make backups of any saved sessions in /home/ssh-mitm/log, then re-run this script with the \"--force\" argument (this will cause the user account to be deleted and re-created)."
            exit -1
        fi
    fi

    return 1
}


# Installs rootless Docker.
function install_rootless_docker {
    echo -e "\n${WHITEB}Installing ${YELLOWB}EXPERIMENTAL${WHITEB} Docker environment for public key authentication MITM'ing...${CLR}\n"

    # If the rootless script isn't installed, then add the Docker repository to apt and install it.
    if [[ ! -f /usr/bin/dockerd-rootless.sh ]]; then

	# Prerequisites taken from: https://docs.docker.com/engine/install/ubuntu/
	apt update
	apt install -y apt-transport-https ca-certificates curl gnupg lsb-release uidmap

	# Download and install the GPG key for Docker package signing.
	# Docker doesn't easily provide the key hash.  Tsk, tsk!
	wget -O - https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

	echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

	echo -e "\n${WHITEB}Installing Docker packages from Docker's repo...${CLR}\n"
	apt update
	apt install -y docker-ce docker-ce-cli containerd.io

	if [[ (! -f /usr/bin/dockerd-rootless-setuptool.sh) || (! -f /usr/bin/dockerd-rootless.sh) ]]; then
	    echo -e "${REDB}Failed to install Docker.${CLR}"
	    exit -1
	fi
    fi

    echo -e "\n${WHITEB}Running /usr/bin/dockerd-rootless-setuptool.sh...${CLR}\n"
    su - ssh-mitm -c "/usr/bin/dockerd-rootless-setuptool.sh install"

    touch /home/ssh-mitm/.bashrc
    echo "export XDG_RUNTIME_DIR=/home/ssh-mitm/.docker/run" >> /home/ssh-mitm/.profile
    echo "export DOCKER_HOST=unix:///home/ssh-mitm/.docker/run/docker.sock" >> /home/ssh-mitm/.profile

    echo -e "\n${WHITEB}Building ssh-mitm-fake-env image...${CLR}\n"
    su - ssh-mitm -c "/usr/bin/dockerd-rootless.sh 2>&1 >> ~/.docker/dockerd.log" &

    # Wait up to 10 seconds for Docker daemon to start (i.e. its socket to open).
    for i in {1..10}; do
       sleep 1
       if [[ -S /home/ssh-mitm/.docker/run/docker.sock ]]; then
           break
       fi
    done

    if [[ $i -ge 10 ]]; then
       echo -e "${REDB}Failed to start rootless Docker daemon!${CLR}"
       exit -1
    fi

    # Put Dockerfile in its own build directory.
    mkdir -m 0700 /home/ssh-mitm/build_fake_env
    cp Dockerfile.fake_env /home/ssh-mitm/build_fake_env
    chown -R ssh-mitm:ssh-mitm /home/ssh-mitm/build_fake_env

    # Now build the image.
    su - ssh-mitm -c "cd build_fake_env; docker build -f Dockerfile.fake_env -t ssh-mitm-fake-env:latest ."

    # Clean up its intermediate staging images.
    su - ssh-mitm -c "docker system prune --force; docker image rm ubuntu:20.04"

    echo -e "\n${WHITEB}Done installing rootless Docker.${CLR}\n"
    return 1
}


# Installs prerequisites.
function install_prereqs {
    echo -e "${WHITEB}Installing prerequisites...${CLR}\n"

    declare -a packages need_openssl_sources
    packages=(autoconf build-essential zlib1g-dev)

    # Check if we are in Kali Linux, Ubuntu 18.04, or Linux Mint 19.  These
    # OSes ship with OpenSSL v1.1.0, which OpenSSH doesn't support.  So we
    # need to explicitly install the v1.0.x dev package.
    #
    # Also, a bare-bones Kali installation may not have the killall tool,
    # so install that in the psmisc package.
    if [[ -f /etc/lsb-release ]]; then
        egrep "Kali|bionic|Linux Mint 19" /etc/lsb-release > /dev/null
    else
        egrep "Kali" /etc/os-release > /dev/null
    fi

    if [[ $? == 0 ]]; then
        packages+=(psmisc)
    else
       # On Linux Mint 20 / Ubuntu 20, there is no package that gives us OpenSSL 1.0.2, so we'll download and compile from sources.
       need_openssl_sources=1
    fi

    echo -e "${WHITEB}Installing packages: ${packages[@]}${CLR}"
    apt install -y ${packages[@]}
    if [[ $? != 0 ]]; then
        echo -e "${REDB}Failed to install prerequisites.${CLR}  Failed: apt install -y ${packages[@]}"
        exit -1
    fi

    # Compile OpenSSL v1.0.2u from sources.
    echo -e "\n${WHITEB}Compiling OpenSSL 1.0.2u...${CLR}"
    pushd $openssl_source_dir > /dev/null
    make clean
    ./config -v -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIC no-shared enable-weak-ssl-ciphers zlib
    make -j $NUM_PROCS depend
    make -j $NUM_PROCS all
    popd > /dev/null

    if [[ (! -f $openssl_source_dir/libssl.a) || (! -f $openssl_source_dir/libcrypto.a) ]]; then
        echo -e "\n${REDB}Failed to build libssl.a and/or libcrypto.a in ${openssl_source_dir} directory!${CLR}"
        exit -1
    fi

    echo -e "\n${GREENB}Successfully built OpenSSL 1.0.2u from sources.${CLR}\n"
    return 1
}


# Applies the MITM patch to OpenSSH and compiles it.
function compile_openssh {
    pushd $openssh_source_dir > /dev/null

    echo -e "${WHITEB}Running autoconf in openssh-7.5p1-mitm/...${CLR}\n"
    autoconf

    echo -e "\n${WHITEB}Done.  Compiling modified OpenSSH sources...${CLR}\n"
    ./configure --with-sandbox=no --with-privsep-user=ssh-mitm --with-privsep-path=/home/ssh-mitm/empty --with-pid-dir=/home/ssh-mitm --with-lastlog=/home/ssh-mitm --with-ssl-dir=../$openssl_source_dir
    make clean
    make -j $NUM_PROCS
    popd > /dev/null

    # Ensure that sshd and ssh were built.
    if [[ (! -f $openssh_source_dir/sshd) || (! -f $openssh_source_dir/ssh) ]]; then
        echo -e "\n${REDB}Failed to build ssh and/or sshd.  Terminating.${CLR}"
        exit -1
    fi

    echo -e "\n${GREENB}Successfully built SSH MITM!${CLR}\n"
}


# Creates the ssh-mitm user account, and sets up its environment.
function setup_environment {
    echo -e "\n${WHITEB}Creating ssh-mitm user, and setting up its environment...${CLR}\n"

    # Create the ssh-mitm user and set its home directory to mode 0700.  Create
    # "bin" and "etc" subdirectories to hold the executables and config file,
    # respectively.
    useradd -m -s /bin/bash ssh-mitm
    chmod 0700 ~ssh-mitm
    mkdir -m 0755 ~ssh-mitm/{bin,etc,log}
    mkdir -m 0700 -p ~ssh-mitm/{tmp,.docker/run}
    chown ssh-mitm:ssh-mitm ~ssh-mitm/{tmp,log}

    # Strip the debugging symbols out of the executables.
    strip $openssh_source_dir/sshd $openssh_source_dir/ssh

    # Make a copy of the ssh client config, since we need to modify it.
    cp $openssh_source_dir/ssh_config $openssh_source_dir/ssh_config.mitm

    # Add explicit algorithm lists to ssh client's config.
    echo -e "\nHostKeyAlgorithms ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-dss\n\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group1-sha1\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,blowfish-cbc,cast128-cbc,3des-cbc,arcfour256,arcfour128,arcfour\n\nMACs umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,umac-64-etm@openssh.com,umac-64@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-ripemd160@openssh.com,hmac-ripemd160,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96,hmac-md5-etm@openssh.com,hmac-md5,hmac-md5-96-etm@openssh.com,hmac-md5-96\n" >> $openssh_source_dir/ssh_config.mitm

    # Copy the config files to the "etc" directory.
    cp $openssh_source_dir/sshd_config ~ssh-mitm/etc/sshd_config
    cp $openssh_source_dir/ssh_config.mitm ~ssh-mitm/etc/ssh_config

    # Copy the executables to the "bin" directory.
    cp $openssh_source_dir/sshd ~ssh-mitm/bin/sshd_mitm
    cp $openssh_source_dir/ssh ~ssh-mitm/bin/ssh

    # Create a 4096-bit RSA host key and ED25519 host key.
    ssh-keygen -t rsa -b 4096 -f /home/ssh-mitm/etc/ssh_host_rsa_key -N ''
    ssh-keygen -t ed25519 -f /home/ssh-mitm/etc/ssh_host_ed25519_key -N ''

    # Create the "empty" directory to make the privsep function happy,
    # as well as the ".ssh" directory (for some reason, this was observed
    # to not be created properly at run-time...).
    mkdir -m 0700 ~ssh-mitm/empty ~ssh-mitm/.ssh

    # Set ownership on some (but not all) paths.
    chown -R ssh-mitm:ssh-mitm /home/ssh-mitm/{empty,.ssh,.docker} /home/ssh-mitm/etc/ssh_host_*key* /home/ssh-mitm

    # Create the "run.sh" script, then set its permissions.
    cat > ~ssh-mitm/run.sh <<EOF
#!/bin/bash
/home/ssh-mitm/bin/sshd_mitm -f /home/ssh-mitm/etc/sshd_config
if [[ \$? == 0 ]]; then
    echo "sshd_mitm is now running."
    exit 0
else
    echo -e "\n\nERROR: sshd_mitm failed to start!\n"
    exit -1
fi
EOF
    chmod 0755 ~ssh-mitm/run.sh

    # If the experimental installation was enabled, install rootless Docker.
    if [[ $1 == "experimental" ]]; then
	install_rootless_docker
    fi

    # Install the AppArmor profiles.
    if [[ ! -d /etc/apparmor.d ]]; then
        mkdir -m 0755 /etc/apparmor.d
    fi
    cp apparmor/home.ssh-mitm.bin.sshd_mitm /etc/apparmor.d/
    cp apparmor/home.ssh-mitm.bin.ssh /etc/apparmor.d/

    # Enable the profiles.
    service apparmor reload 2> /dev/null

    # If AppArmor isn't installed, give Kali users a chance to install it
    # automatically (if Kali is installed to disk).  For other distros,
    # simply print a warning.
    if [[ $? != 0 ]]; then

        # Is this Kali Linux?
        grep Kali /etc/os-release > /dev/null
        if [[ $? == 0 ]]; then

            # Is Kali installed, or is it a Live CD boot?
            if [[ -f /etc/default/grub ]]; then  # Its installed.
                echo -e -n "\n${YELLOWB}Kali Linux detected with no AppArmor installed.  For added safety, it is highly recommended (though not required) that sshd_mitm is run in a restricted environment.  Would you like to automatically enable AppArmor? (y/n) "
                read -n 1 install_apparmor
                echo -e "\n"

                # If the user chose to install AppArmor...
                if [[ ($install_apparmor == 'y') || ($install_apparmor == 'Y') ]]; then
                    echo -e "${WHITEB}Getting apparmor from repository...${CLR}\n"
                    apt -y install apparmor

                    echo -e "\n${WHITEB}Enabling AppArmor on startup...${CLR}\n"
                    update-rc.d apparmor enable

                    echo -e "\n${WHITEB}Updating bootloader...${CLR}\n"
                    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet apparmor=1 security=apparmor"/' /etc/default/grub
                    update-grub2

                    echo -e "\n${WHITEB}Finished installing AppArmor.  Reboot to enable it.${CLR}\n"
                else  # User declined to install AppArmor.
                    echo -e "\n${YELLOWB}AppArmor will not be automatically installed.${CLR}"
                fi
            else  # Kali Live CD boot.
                echo -e "\n\n\t${YELLOWB}!!! WARNING !!!:${CLR} AppArmor is not available on Kali Live instances.  For added safety, it is highly recommended (though not required) that sshd_mitm is run in a restricted environment.  Installing Kali to a disk would allow AppArmor to be enabled.\n"
            fi

        else  # This is not Kali Linux.
            echo -e "\n\n\t${YELLOWB}!!! WARNING !!!:${CLR} AppArmor is not installed.  It is highly recommended (though not required) that sshd_mitm is run in a restricted environment.\n\n\tInstall AppArmor with: \"apt install apparmor\".\n"
        fi
    fi
}


if [[ `id -u` != 0 ]]; then
    echo -e "${REDB}Error: this script must be run as root.${CLR}"
    exit -1
fi

if [[ ($# < 1) || ($# > 2) ||
      (($1 != "default") && ($1 != "experimental")) ||
      (($# == 2) && ($2 != "--force")) ]]; then
    echo "Usage: $0 [default|experimental] [--force]"
    echo
    echo "  default:       installs default production system"
    echo "  experimental:  installs experimental features (i.e.: rootless Docker support"
    echo "                     for public key authentication MITM'ing)"
    echo
    echo "  --force:       forces re-installation over an existing install"
    echo
    exit -1
fi

install_type=$1
force_flag=$2

install_prereqs
reset_env $force_flag
compile_openssh
setup_environment $install_type

echo -e "\n\n${GREENB}Done!${WHITEB}  The next step is to use JoesAwesomeSSHMITMVictimFinder.py to find target IPs, then execute start.sh and ARP spoof.${CLR}\n\n"
exit 0
