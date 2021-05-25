/* $OpenBSD: sftp-client.h,v 1.27 2015/05/08 06:45:13 djm Exp $ */

/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Client side of SSH2 filexfer protocol */

#ifndef _SFTP_CLIENT_H
#define _SFTP_CLIENT_H

#include <sys/statvfs.h>
#include "misc.h"

#ifdef USE_SYSTEM_GLOB
# include <glob.h>
#else
# include "openbsd-compat/glob.h"
#endif

typedef struct SFTP_DIRENT SFTP_DIRENT;

struct SFTP_DIRENT {
	char *filename;
	char *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
struct sftp_statvfs {
	u_int64_t f_bsize;
	u_int64_t f_frsize;
	u_int64_t f_blocks;
	u_int64_t f_bfree;
	u_int64_t f_bavail;
	u_int64_t f_files;
	u_int64_t f_ffree;
	u_int64_t f_favail;
	u_int64_t f_fsid;
	u_int64_t f_flag;
	u_int64_t f_namemax;
};

struct sftp_conn {
	int fd_in;
	int fd_out;
	u_int transfer_buflen;
	u_int num_requests;
	u_int version;
	u_int msg_id;
#define SFTP_EXT_POSIX_RENAME	0x00000001
#define SFTP_EXT_STATVFS	0x00000002
#define SFTP_EXT_FSTATVFS	0x00000004
#define SFTP_EXT_HARDLINK	0x00000008
#define SFTP_EXT_FSYNC		0x00000010
	u_int exts;
	u_int64_t limit_kbps;
	struct bwlimit bwlimit_in, bwlimit_out;
};

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
struct sftp_conn *do_init(int, int, u_int, u_int, u_int64_t);

u_int sftp_proto_version(struct sftp_conn *);

/* Close file referred to by 'handle' */
int do_close(struct sftp_conn *, const u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
int do_readdir(struct sftp_conn *, const char *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from do_readdir) */
void free_sftp_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
int do_rm(struct sftp_conn *, const char *);

/* Create directory 'path' */
int do_mkdir(struct sftp_conn *, const char *, Attrib *, int);

/* Remove directory 'path' */
int do_rmdir(struct sftp_conn *, const char *);

/* Get file attributes of 'path' (follows symlinks) */
Attrib *do_stat(struct sftp_conn *, const char *, int, u_int *);

/* Get file attributes of 'path' (does not follow symlinks) */
Attrib *do_lstat(struct sftp_conn *, const char *, int, u_int *);

/* Set file attributes of 'path' */
int do_setstat(struct sftp_conn *, const char *, Attrib *);

/* Set file attributes of open file 'handle' */
int do_fsetstat(struct sftp_conn *, const u_char *, u_int, Attrib *);

/* Canonicalise 'path' - caller must free result */
char *do_realpath(struct sftp_conn *, const char *, u_int *);

/* Get statistics for filesystem hosting file at "path" */
int do_statvfs(struct sftp_conn *, const char *, struct sftp_statvfs *, int);

/* Rename 'oldpath' to 'newpath' */
int do_rename(struct sftp_conn *, const char *, const char *, int force_legacy);

/* Link 'oldpath' to 'newpath' */
int do_hardlink(struct sftp_conn *, const char *, const char *);

/* Rename 'oldpath' to 'newpath' */
int do_symlink(struct sftp_conn *, const char *, const char *);

/* Call fsync() on open file 'handle' */
int do_fsync(struct sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
int do_download(struct sftp_conn *, const char *, const char *,
    Attrib *, int, int, int);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
int download_dir(struct sftp_conn *, const char *, const char *,
    Attrib *, int, int, int, int);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
int do_upload(struct sftp_conn *, const char *, const char *, int, int, int);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
int upload_dir(struct sftp_conn *, const char *, const char *, int, int, int,
    int);

/* Concatenate paths, taking care of slashes. Caller must free result. */
char *path_append(const char *, const char *);

u_int mitm_do_close(struct sftp_conn *conn, const u_char *handle, u_int handle_len);

u_int mitm_do_fsetstat(struct sftp_conn *conn, const u_char *handle, u_int handle_len, Attrib *a);

Attrib *mitm_do_fstat(struct sftp_conn *conn, const u_char *handle, u_int handle_len, int quiet, u_int *status);

int mitm_do_fstatvfs(struct sftp_conn *conn, const u_char *handle, size_t handle_len, struct statvfs *st, u_int *status);

u_int mitm_do_fsync(struct sftp_conn *conn, u_char *handle, size_t handle_len);

u_int mitm_do_hardlink(struct sftp_conn *conn, const char *oldpath, const char *newpath);

u_int mitm_do_mkdir(struct sftp_conn *conn, const char *path, Attrib *a);

u_char *mitm_do_open(struct sftp_conn *conn, char *remote_path, u_int32_t pflags, Attrib *a, size_t *handle_len, u_int *status);

u_char *mitm_do_opendir(struct sftp_conn *conn, const char *path, size_t *handle_len, int *status);

u_char *mitm_do_read(struct sftp_conn *conn, const u_char *handle, u_int handle_len, u_int64_t offset, u_int32_t read_len, size_t *ret_len, u_int *status);

Stat *mitm_do_readdir(struct sftp_conn *conn, u_int32_t id, u_char *handle_str, size_t handle_len, u_int *count, int *status);

int mitm_do_readlink(struct sftp_conn *conn, const char *path, u_int *status, char **filename, char **longname, Attrib *a);

u_int mitm_do_rename(struct sftp_conn *conn, const char *oldpath, const char *newpath, int force_legacy);

u_int mitm_do_rmdir(struct sftp_conn *conn, const char *path);

u_int mitm_do_rm(struct sftp_conn *conn, const char *path);

u_int mitm_do_setstat(struct sftp_conn *conn, const char *path, Attrib *a);

int mitm_do_statvfs(struct sftp_conn *conn, const char *path, struct statvfs *st, u_int *status);

u_int mitm_do_symlink(struct sftp_conn *conn, const char *oldpath, const char *newpath);

u_int mitm_do_write(struct sftp_conn *conn, const u_char *handle, u_int handle_len, u_int64_t offset, u_char *buf, u_int buf_len);

#endif
