#	$OpenBSD: stderr-data.sh,v 1.4 2015/03/03 22:35:19 markus Exp $
#	Placed in the Public Domain.

tid="stderr data transfer"

for n in '' -n; do
for p in ${SSH_PROTOCOLS}; do
	verbose "test $tid: proto $p ($n)"
	${SSH} $n -$p -F $OBJ/ssh_proxy otherhost \
		exec sh -c \'"exec > /dev/null; sleep 3; cat ${DATA} 1>&2 $s"\' \
		2> ${COPY}
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh failed with exit code $r"
	fi
	cmp ${DATA} ${COPY}	|| fail "stderr corrupt"
	rm -f ${COPY}

	${SSH} $n -$p -F $OBJ/ssh_proxy otherhost \
		exec sh -c \'"echo a; exec > /dev/null; sleep 3; cat ${DATA} 1>&2 $s"\' \
		> /dev/null 2> ${COPY}
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh failed with exit code $r"
	fi
	cmp ${DATA} ${COPY}	|| fail "stderr corrupt"
	rm -f ${COPY}
done
done
