#!/bin/bash

# install.sh
# Copyright (C) 2017-2019, Joe Testa <jtesta@positronsecurity.com>
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

openssh_sources='openssh-7.5p1.tar.gz'
openssh_source_dir='openssh-7.5p1'
mitm_patch='openssh-7.5p1-mitm.patch'


# Resets the environment (in case this script was run once before).
function reset_env {

    # Remove files previously downloaded.
    rm -rf *.asc $openssh_sources $openssh_source_dir $openssh_source_dir-mitm

    # Make sure no sshd_mitm is running and the user is logged out.
    killall -u ssh-mitm 2> /dev/null

    # Check if the ssh-mitm user exists.
    id ssh-mitm > /dev/null 2> /dev/null
    if [[ $? == 0 ]]; then

	# The user exists.  If this script was run with the "--force" argument,
        # then we will delete the user.
        if [[ $1 == '--force' ]]; then
            userdel -f -r ssh-mitm 2> /dev/null

        # There could be saved sessions from an old version of SSH MITM that
        # we shouldn't destroy automatically.
        else
            echo "It appears that the ssh-mitm user already exists.  Make backups of any saved sessions in /home/ssh-mitm/, then re-run this script with the \"--force\" argument (this will cause the user account to be deleted and re-created)."
            exit -1
        fi
    fi

    return 1
}


# Installs prerequisites.
function install_prereqs {
    echo -e "Installing prerequisites...\n"

    declare -a packages
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
        packages+=(libssl1.0-dev psmisc)
    else
        packages+=(libssl-dev)
    fi

    apt install -y ${packages[@]}
    if [[ $? != 0 ]]; then
        echo -e "Failed to install prerequisites.  Failed: apt install -y ${packages[@]}"
        exit -1
    fi

    return 1
}


# Downloads OpenSSH and verifies its sources.
function get_openssh {
    local openssh_sig='openssh-7.5p1.tar.gz.asc'
    local release_key_fingerprint_expected='59C2 118E D206 D927 E667  EBE3 D3E5 F56B 6D92 0D30'
    local openssh_checksum_expected='9846e3c5fab9f0547400b4d2c017992f914222b3fd1f8eee6c7dc6bc5e59f9f0'

    echo -e "\nGetting OpenSSH release key...\n"
    wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc

    echo -e "\nGetting OpenSSH sources...\n"
    wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/$openssh_sources

    echo -e "\nGetting OpenSSH signature...\n"
    wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/$openssh_sig

    echo -e "\nImporting OpenSSH release key...\n"
    gpg --import RELEASE_KEY.asc

    local release_key_fingerprint_actual=`gpg --fingerprint 6D920D30`
    if [[ $release_key_fingerprint_actual != *"$release_key_fingerprint_expected"* ]]; then
        echo -e "\nError: OpenSSH release key fingerprint does not match expected value!\n\tExpected: $release_key_fingerprint_expected\n\tActual: $release_key_fingerprint_actual\n\nTerminating."
        exit -1
    fi
    echo -e "\n\nOpenSSH release key matches expected value.\n"

    # Check GPG's return value.  0 denotes a valid signature, and 1 is returned
    # on invalid signatures.
    local gpg_verify=`gpg --verify $openssh_sig $openssh_sources 2>&1`
    if [[ $? != 0 ]]; then
        echo -e "\n\nError: OpenSSH signature invalid!  Verification returned code: $?\n\nTerminating."
        rm -f $openssh_sources
        exit -1
    fi

    echo -e "Signature on OpenSSH sources verified.\n"

    local openssh_checksum_actual=`sha256sum $openssh_sources`
    if [[ $openssh_checksum_actual != "$openssh_checksum_expected"* ]]; then
        echo -e "Error: OpenSSH checksum is invalid!  Terminating."
        exit -1
    fi

    return 1
}


# Applies the MITM patch to OpenSSH and compiles it.
function compile_openssh {
    tar xzf $openssh_sources --no-same-owner
    if [ ! -d $openssh_source_dir ]; then
       echo "Failed to decompress OpenSSH sources!"
       exit -1
    fi
    mv $openssh_source_dir "$openssh_source_dir"-mitm
    openssh_source_dir="$openssh_source_dir"-mitm

    pushd $openssh_source_dir > /dev/null
    echo -e "Patching OpenSSH sources...\n"
    patch -p1 < ../$mitm_patch

    if [[ $? != 0 ]]; then
        echo "Failed to patch sources!: patch returned $?"
        exit -1
    fi

    echo -e "\nDone.  Running autoconf...\n"
    autoconf

    echo -e "\nDone.  Compiling modified OpenSSH sources...\n"

    ./configure --with-sandbox=no --with-privsep-user=ssh-mitm --with-privsep-path=/home/ssh-mitm/empty --with-pid-dir=/home/ssh-mitm --with-lastlog=/home/ssh-mitm
    make -j `nproc --all`
    popd > /dev/null

    # Ensure that sshd and ssh were built.
    if [[ (! -f $openssh_source_dir/sshd) || (! -f $openssh_source_dir/ssh) ]]; then
        echo -e "\nFailed to build ssh and/or sshd.  Terminating."
        exit -1
    fi
}


# Creates the ssh-mitm user account, and sets up its environment.
function setup_environment {
    echo -e "\nCreating ssh-mitm user, and setting up its environment...\n"

    # Create the ssh-mitm user and set its home directory to mode 0700.  Create
    # "bin" and "etc" subdirectories to hold the executables and config file,
    # respectively.
    useradd -m -s /bin/bash ssh-mitm
    chmod 0700 ~ssh-mitm
    mkdir -m 0755 ~ssh-mitm/{bin,etc}
    mkdir -m 0700 ~ssh-mitm/tmp
    chown ssh-mitm:ssh-mitm ~ssh-mitm/tmp

    # Copy the config files to the "etc" directory.
    cp $openssh_source_dir/sshd_config ~ssh-mitm/etc/
    cp $openssh_source_dir/ssh_config ~ssh-mitm/etc/

    # Add explicit algorithm lists to ssh client's config.
    echo -e "\nHostKeyAlgorithms ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-dss\n\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group1-sha1\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,blowfish-cbc,cast128-cbc,3des-cbc,arcfour256,arcfour128,arcfour\n\nMACs umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,umac-64-etm@openssh.com,umac-64@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-ripemd160@openssh.com,hmac-ripemd160,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96,hmac-md5-etm@openssh.com,hmac-md5,hmac-md5-96-etm@openssh.com,hmac-md5-96\n" >> ~ssh-mitm/etc/ssh_config

    # Copy the executables to the "bin" directory.
    cp $openssh_source_dir/sshd ~ssh-mitm/bin/sshd_mitm
    cp $openssh_source_dir/ssh ~ssh-mitm/bin/ssh

    # Strip the debugging symbols out of the executables.
    strip ~ssh-mitm/bin/sshd_mitm ~ssh-mitm/bin/ssh

    # Create a 4096-bit RSA host key and ED25519 host key.
    ssh-keygen -t rsa -b 4096 -f /home/ssh-mitm/etc/ssh_host_rsa_key -N ''
    ssh-keygen -t ed25519 -f /home/ssh-mitm/etc/ssh_host_ed25519_key -N ''

    # Create the "empty" directory to make the privsep function happy,
    # as well as the ".ssh" directory (for some reason, this was observed
    # to not be created properly at run-time...).
    mkdir -m 0700 ~ssh-mitm/empty ~ssh-mitm/.ssh

    # Set ownership on the "empty" directory and SSH host keys.
    chown ssh-mitm:ssh-mitm /home/ssh-mitm/empty /home/ssh-mitm/.ssh /home/ssh-mitm/etc/ssh_host_*key*

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
                echo -e -n "\nKali Linux detected with no AppArmor installed.  For added safety, it is highly recommended (though not required) that sshd_mitm is run in a restricted environment.  Would you like to automatically enable AppArmor? (y/n) "
                read -n 1 install_apparmor
                echo -e "\n"

                # If the user chose to install AppArmor...
                if [[ ($install_apparmor == 'y') || ($install_apparmor == 'Y') ]]; then
                    echo -e "Getting apparmor from repository...\n"
                    apt -y install apparmor

                    echo -e "\nEnabling AppArmor on startup...\n"
                    update-rc.d apparmor enable

                    echo -e "\nUpdating bootloader...\n"
                    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet apparmor=1 security=apparmor"/' /etc/default/grub
                    update-grub2

                    echo -e "\nFinished installing AppArmor.  Reboot to enable it.\n"
                else  # User declined to install AppArmor.
                    echo -e "\nAppArmor will not be automatically installed."
                fi
            else  # Kali Live CD boot.
                echo -e "\n\n\t!!! WARNING !!!: AppArmor is not available on Kali Live instances.  For added safety, it is highly recommended (though not required) that sshd_mitm is run in a restricted environment.  Installing Kali to a disk would allow AppArmor to be enabled.\n"
            fi

        else  # This is not Kali Linux.
            echo -e "\n\n\t!!! WARNING !!!: AppArmor is not installed.  It is highly recommended (though not required) that sshd_mitm is run in a restricted environment.\n\n\tInstall AppArmor with: \"apt install apparmor\".\n"
        fi
    fi
}


if [[ `id -u` != 0 ]]; then
    echo "Error: this script must be run as root."
    exit -1
fi

install_prereqs
reset_env $1
get_openssh
compile_openssh
setup_environment

echo -e "\n\nDone!  The next step is to use JoesAwesomeSSHMITMVictimFinder.py to find target IPs, then execute start.sh and ARP spoof.\n\n"
exit 0
