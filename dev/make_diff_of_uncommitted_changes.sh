#!/bin/bash

# This script will apply the existing, committed patch to a new directory of
# sources, then diff it with "openssh-7.5p1-mitm/".  The result is stored in
# "uncommitted_changes.patch".

if [[ ! -f openssh-7.5p1.tar.gz ]]; then
    echo -e "\nCan't find openssh-7.5p1.tar.gz.  Ensure that you're in the top level directory of the SSH MITM project."
    exit -1
fi

git diff-index HEAD | grep openssh-7.5p1-mitm.patch
if [[ $? != 1 ]]; then
    echo "Error: it appears that openssh-7.5p1-mitm.patch already has uncommitted changes!"
    exit -1
fi

rm -rf openssh-7.5p1-previous uncommitted_changes.patch
tar xzf openssh-7.5p1.tar.gz
mv openssh-7.5p1 openssh-7.5p1-previous

pushd openssh-7.5p1-previous > /dev/null
patch -p1 < ../openssh-7.5p1-mitm.patch > /dev/null
popd > /dev/null

pushd openssh-7.5p1-mitm > /dev/null
make clean > /dev/null
popd > /dev/null

diff -ru --new-file -x '*~' -x 'config.*' -x Makefile -x opensshd.init -x survey.sh -x openssh.xml -x buildpkg.sh -x output.0 -x requests -x traces.0 -x configure openssh-7.5p1-previous openssh-7.5p1-mitm/ > uncommitted_changes.patch

if [[ -f uncommitted_changes.patch ]]; then
    echo -e "\nuncommitted_changes.patch created."
else
    echo -e "\nFailed to create uncommitted_changes.patch."
fi

rm -rf openssh-7.5p1-previous
exit 0
