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
# This script will regenerate the openssh-7.5p1-mitm.patch file, then launch
# "git diff" on it for manual review.

if [[ (! -d openssh-7.5p1-mitm) || (! -f openssh-7.5p1.tar.gz) ]]; then
    echo -e "\nCould not find openssh-7.5p1-mitm directory or openssh-7.5p1.tar.gz file.  Ensure that you are in the top level directory of the SSH MITM project."
    exit -1
fi

rm -rf openssh-7.5p1
tar xzf openssh-7.5p1.tar.gz

pushd openssh-7.5p1-mitm > /dev/null
make clean > /dev/null
popd > /dev/null

diff -ru --new-file -x '*~' -x 'config.*' -x Makefile -x opensshd.init -x survey.sh -x openssh.xml -x buildpkg.sh -x output.0 -x requests -x traces.0 -x configure openssh-7.5p1 openssh-7.5p1-mitm/ > openssh-7.5p1-mitm.patch

rm -rf openssh-7.5p1

git diff openssh-7.5p1-mitm.patch
exit 0
