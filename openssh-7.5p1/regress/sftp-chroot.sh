#	$OpenBSD: sftp-chroot.sh,v 1.5 2016/09/26 21:34:38 bluhm Exp $
#	Placed in the Public Domain.

tid="sftp in chroot"

CHROOT=/var/run
FILENAME=testdata_${USER}
PRIVDATA=${CHROOT}/${FILENAME}

if [ -z "$SUDO" -a ! -w /var/run ]; then
  echo "skipped: need SUDO to create file in /var/run, test won't work without"
  exit 0
fi

if ! $OBJ/check-perm -m chroot "$CHROOT" ; then
  echo "skipped: $CHROOT is unsuitable as ChrootDirectory"
  exit 0
fi

$SUDO sh -c "echo mekmitastdigoat > $PRIVDATA" || \
	fatal "create $PRIVDATA failed"

start_sshd -oChrootDirectory=$CHROOT -oForceCommand="internal-sftp -d /"

verbose "test $tid: get"
${SFTP} -S "$SSH" -F $OBJ/ssh_config host:/${FILENAME} $COPY \
    >>$TEST_REGRESS_LOGFILE 2>&1 || \
	fatal "Fetch ${FILENAME} failed"
cmp $PRIVDATA $COPY || fail "$PRIVDATA $COPY differ"

$SUDO rm $PRIVDATA
