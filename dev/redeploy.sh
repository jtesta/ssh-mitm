#!/bin/bash
#
# Copyright (C) 2017-2018  Joe Testa <jtesta@positronsecurity.com>
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
#
#
#
# This script is used during the development process to compile and re-deploy
# sshd_mitm.

killall -u ssh-mitm

pushd openssh-7.5p1-mitm
if [[ $1 == 'clean' ]]; then
   make clean
   make -j 10 > /dev/null
else
   make -j 10
fi
popd

if [[ (! -f openssh-7.5p1-mitm/sshd) || (! -f openssh-7.5p1-mitm/ssh) ]]; then
   echo -e "\n\t!!!! Compile error !!!!\n"
   exit -1
fi

cp openssh-7.5p1-mitm/sshd ~ssh-mitm/bin/sshd_mitm
cp openssh-7.5p1-mitm/ssh ~ssh-mitm/bin/ssh
su - ssh-mitm -c "./run.sh"
