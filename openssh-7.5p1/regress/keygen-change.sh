#	$OpenBSD: keygen-change.sh,v 1.5 2015/03/03 22:35:19 markus Exp $
#	Placed in the Public Domain.

tid="change passphrase for key"

S1="secret1"
S2="2secret"

KEYTYPES=`${SSH} -Q key-plain`
if ssh_version 1; then
	KEYTYPES="${KEYTYPES} rsa1"
fi

for t in $KEYTYPES; do
	# generate user key for agent
	trace "generating $t key"
	rm -f $OBJ/$t-key
	${SSHKEYGEN} -q -N ${S1} -t $t -f $OBJ/$t-key
	if [ $? -eq 0 ]; then
		${SSHKEYGEN} -p -P ${S1} -N ${S2} -f $OBJ/$t-key > /dev/null
		if [ $? -ne 0 ]; then
			fail "ssh-keygen -p failed for $t-key"
		fi
	else
		fail "ssh-keygen for $t-key failed"
	fi
	rm -f $OBJ/$t-key $OBJ/$t-key.pub
done
