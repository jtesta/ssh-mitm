/* $OpenBSD: sftp-server.c,v 1.110 2016/09/12 01:22:38 deraadt Exp $ */
/*
 * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "match.h"
#include "uidswap.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "lol.h"

/* Our verbosity */
static LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
static struct passwd *pw = NULL;
static char *client_addr = NULL;

/* input and output queue */
struct sshbuf *iqueue;
struct sshbuf *oqueue;

/* Version of client */
static u_int version;

/* SSH2_FXP_INIT received */
static int init_done;

/* Disable writes */
static int readonly;

/* Requests that are allowed/denied */
static char *request_whitelist, *request_blacklist;

pid_t sshpid = -1;
volatile sig_atomic_t interrupted = 0;
int showprogress = 0;
extern struct sftp_conn *client_conn;
int session_log_fd = -1;      /* A descriptor to this session's log file. */
char *session_log_dir = NULL; /* The directory to store SFTP files in. */

#define MITM_HANDLE_TYPE_FILE 0
#define MITM_HANDLE_TYPE_DIR 1

/* This maps a remote server's handle to a local file descriptor. */
typedef struct MITMHandle MITMHandle;
struct MITMHandle {
  int in_use;          /* If 1, this slot is in use, otherwise it is unallocated.  */
  u_int type;          /* One of the MITM_HANDLE_TYPE_ flags. */
  char *handle_str;    /* The file handle on the remote server. */
  size_t handle_len;   /* The number of bytes the above file handle is. */
  int fd;              /* The local file descriptor. */
  u_int32_t pflags;    /* The portable flags this file was opened with. */
  char *original_path; /* The full path of the original file transferred. */
  char *actual_path;   /* The relative path that the file was saved to locally. */
  char *file_listing;  /* The file listing (if type == MITM_HANDLE_TYPE_DIR). */
  size_t file_listing_size; /* The size of the file_listing buffer. */
};

MITMHandle *mitm_handles = NULL; /* Our array of handles. */
u_int num_mitm_handles = 0;  /* The current size of the mitm_handles array. */

/* When mitm_handles runs out of free slots, it will grow by this many. */
#define MITM_HANDLES_NEW_BLOCK 16

/* The block size that the MITMHandle.file_listing buffer grows by. */
#define MITM_HANDLES_FILE_LISTING_BLOCK 1024


/* Packet handlers */
static void process_open(u_int32_t id);
static void process_close(u_int32_t id);
static void process_read(u_int32_t id);
static void process_write(u_int32_t id);
static void process_stat(u_int32_t id);
static void process_lstat(u_int32_t id);
static void process_fstat(u_int32_t id);
static void process_setstat(u_int32_t id);
static void process_fsetstat(u_int32_t id);
static void process_opendir(u_int32_t id);
static void process_readdir(u_int32_t id);
static void process_remove(u_int32_t id);
static void process_mkdir(u_int32_t id);
static void process_rmdir(u_int32_t id);
static void process_realpath(u_int32_t id);
static void process_rename(u_int32_t id);
static void process_readlink(u_int32_t id);
static void process_symlink(u_int32_t id);
static void process_extended_posix_rename(u_int32_t id);
static void process_extended_statvfs(u_int32_t id);
static void process_extended_fstatvfs(u_int32_t id);
static void process_extended_hardlink(u_int32_t id);
static void process_extended_fsync(u_int32_t id);
static void process_extended(u_int32_t id);

struct sftp_conn *make_connection(char *host, unsigned short port, char *username, char *password_and_fingerprint_socket_name);
void mitm_init_log(char *log_filepath, char *log_dir);
void mitm_handle_close(const char *handle_str, size_t handle_len);
void mitm_handle_free(MITMHandle *mh);
void mitm_handle_init(MITMHandle *mh);
void mitm_handle_new(u_int type, char *original_name, u_int32_t pflags, const char *handle_str, size_t handle_len);
void mitm_handle_read_write(char *handle_str, size_t handle_len, u_int64_t offset, u_char *buf, size_t buf_len);
MITMHandle *mitm_handle_search(const char *handle_str, size_t handle_len);
void sftp_log(u_int status, const char *fmt, ...);
void sftp_log_no_filter(u_int status, const char *fmt, ...);
void _sftp_log(u_int status, u_int do_xss_filtering, char *buf, int buf_len);
void sftp_log_close(u_int status, char *handle_str, size_t handle_len);
void sftp_log_attrib(const char *func, u_int status, char *name, Attrib *a);
void sftp_log_handle_attrib(const char *func, u_int status, char *handle_str, size_t handle_len, Attrib *a);
void sftp_log_readdir(char *handle_str, size_t handle_len, char *listing);
void sftp_log_statvfs(u_int status, char *path, struct statvfs *st);
void sftp_log_fstatvfs(u_int status, char *handle_str, size_t handle_len, struct statvfs *st);
void sftp_log_fsync(u_int status, char *handle_str, size_t handle_len);
void xss_sanitize(char *buf, int buf_len);

/* The error message for functions that search for file handles. */
#define CANT_FIND_HANDLE "MITM: %s: can't find handle!"

struct sftp_handler {
	const char *name;	/* user-visible name for fine-grained perms */
	const char *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	void (*handler)(u_int32_t);
	int does_write;		/* if nonzero, banned for readonly mode */
};

struct sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", NULL, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", NULL, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", NULL, SSH2_FXP_READ, process_read, 0 },
	{ "write", NULL, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", NULL, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", NULL, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", NULL, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", NULL, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", NULL, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", NULL, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", NULL, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", NULL, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", NULL, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", NULL, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", NULL, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", NULL, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", NULL, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", NULL, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ NULL, NULL, 0, NULL, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
struct sftp_handler extended_handlers[] = {
	{ "posix-rename", "posix-rename@openssh.com", 0,
	   process_extended_posix_rename, 1 },
	{ "statvfs", "statvfs@openssh.com", 0, process_extended_statvfs, 0 },
	{ "fstatvfs", "fstatvfs@openssh.com", 0, process_extended_fstatvfs, 0 },
	{ "hardlink", "hardlink@openssh.com", 0, process_extended_hardlink, 1 },
	{ "fsync", "fsync@openssh.com", 0, process_extended_fsync, 1 },
	{ NULL, NULL, 0, NULL, 0 }
};

static int
request_permitted(struct sftp_handler *h)
{
	char *result;

	if (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		return 0;
	}
	if (request_blacklist != NULL &&
	    ((result = match_list(h->name, request_blacklist, NULL))) != NULL) {
		free(result);
		verbose("Refusing blacklisted %s request", h->name);
		return 0;
	}
	if (request_whitelist != NULL &&
	    ((result = match_list(h->name, request_whitelist, NULL))) != NULL) {
		free(result);
		debug2("Permitting whitelisted %s request", h->name);
		return 1;
	}
	if (request_whitelist != NULL) {
		verbose("Refusing non-whitelisted %s request", h->name);
		return 0;
	}
	return 1;
}

/*
static int
errno_to_portable(int unixerrno)
{
	int ret = 0;

	switch (unixerrno) {
	case 0:
		ret = SSH2_FX_OK;
		break;
	case ENOENT:
	case ENOTDIR:
	case EBADF:
	case ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		break;
	case EPERM:
	case EACCES:
	case EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		break;
	case ENAMETOOLONG:
	case EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		break;
	case ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		break;
	default:
		ret = SSH2_FX_FAILURE;
		break;
	}
	return ret;
}

static int
flags_from_portable(int pflags)
{
	int flags = 0;

	if ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} else if (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} else if (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	if (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	if (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	if (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	if (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	return flags;
}
*/
static const char *
string_from_portable(int pflags)
{
	static char ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		if (*ret != '\0')			\
			strlcat(ret, ",", sizeof(ret));	\
		strlcat(ret, str, sizeof(ret));		\
	}

	if (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	if (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	if (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	if (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	if (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	if (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	return ret;
}


/* handle handles */

typedef struct Handle Handle;
struct Handle {
	int use;
	DIR *dirp;
	int fd;
	int flags;
	char *name;
	u_int64_t bytes_read, bytes_write;
	int next_unused;
};

enum {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

Handle *handles = NULL;
u_int num_handles = 0;
int first_unused_handle = -1;


/* Frees a handle slot and re-initializes it. */
void mitm_handle_free(MITMHandle *mh) {
  if (mh != NULL) {
    free(mh->handle_str);
    free(mh->original_path);
    free(mh->actual_path);
    free(mh->file_listing);
    mitm_handle_init(mh);
  }
}

/* Initializes a handle slot. Use mitm_handle_free() on previously-occupied
 * slots. */
void mitm_handle_init(MITMHandle *mh) {
  if (mh != NULL) {
    mh->in_use = 0;
    mh->type = 0;
    mh->handle_str = NULL;
    mh->handle_len = 0;
    mh->fd = -1;
    mh->pflags = 0;
    mh->original_path = NULL;
    mh->actual_path = NULL;
    mh->file_listing = NULL;
    mh->file_listing_size = 0;
  }
}

/* Adds a new handle, given its type (MITM_HANDLE_TYPE_{FILE,DIR}), original
 * path, open flags, and remote server handle. */
void mitm_handle_new(u_int type, char *original_path, u_int32_t pflags, const char *handle_str, size_t handle_len) {
  int unused_handle = -1, actual_path_len = 0;;
  u_int i = 0, num_tries = 0, r = 0;
  char file_path[PATH_MAX];
  char *file_prefix = NULL, *temp_name = NULL, *log_dir = NULL;

  /* On first invokation, the mitm_handles array is unallocated. */
  if (mitm_handles == NULL) {
    if ((mitm_handles = reallocarray(NULL, MITM_HANDLES_NEW_BLOCK, sizeof(MITMHandle))) == NULL)
      fatal("Could not allocate array for MITMHandles.");

    num_mitm_handles = MITM_HANDLES_NEW_BLOCK;

    /* Initializes all the slots. */
    for (i = 0; i < num_mitm_handles; i++)
      mitm_handle_init(&mitm_handles[i]);

    /* Since we just allocated a new array, we know slot 0 is unoccupied. */
    unused_handle = 0;
  }

  /* Sequentially search for an unused slot in the array. */
  for (i = 0; (i < num_mitm_handles) && (unused_handle == -1); i++) {
    /* If we found one, save its slot index. */
    if (mitm_handles[i].in_use == 0)
      unused_handle = i;
  }

  /* If, after searching the entire array, we haven't found an open slot, we
   * must grow the array. */
  if (unused_handle == -1) {
    unused_handle = num_mitm_handles;

    /* Make the array bigger by one block size. */
    num_mitm_handles += MITM_HANDLES_NEW_BLOCK;
    if ((mitm_handles = reallocarray(mitm_handles, num_mitm_handles, sizeof(MITMHandle))) == NULL)
      fatal("Could not allocate array for MITMHandles.");

    /* Initialize the slots we just expanded. */
    for (; i < num_mitm_handles; i++)
      mitm_handle_init(&mitm_handles[i]);
  }

  /* Mark this slot as being in use. */
  mitm_handles[unused_handle].in_use = 1;

  /* Set the file/directory flag. */
  mitm_handles[unused_handle].type = type;

  /* Allocate a buffer for the remote server handle data, then copy it. */
  if ((mitm_handles[unused_handle].handle_str = xmalloc(handle_len)) == NULL)
    fatal("Could not allocate array for handle string.");
  memcpy(mitm_handles[unused_handle].handle_str, handle_str, handle_len);

  /* Set the handle length. */
  mitm_handles[unused_handle].handle_len = handle_len;

  /* Copy the original full path of the file being opened on the remote
   * server, and do XSS filtering on it. */
  mitm_handles[unused_handle].original_path = xstrdup(original_path);
  xss_sanitize(mitm_handles[unused_handle].original_path, strlen(mitm_handles[unused_handle].original_path));

  /* Save the portable flags its being opened with. */
  mitm_handles[unused_handle].pflags = pflags;

  /* If this is a file, find a unique local filename, and open a handle to
   * it. */
  if (type == MITM_HANDLE_TYPE_FILE) {

    /* Extract the filename of the path. */
    temp_name = xstrdup(original_path);
    file_prefix = basename(temp_name);

    /* Ensure that a relative path wasn't snuck in. */
    if ((memmem(file_prefix, strlen(file_prefix), "..", 2) != NULL) || (memmem(file_prefix, strlen(file_prefix), "/", 1) != NULL))
      file_prefix = "file";

    /* Construct a path to save the file to locally, such as
     * "/home/ssh-mitm/sftp_session_0/lol.txt". */
    snprintf(file_path, sizeof(file_path) - 1, "%s%s", session_log_dir, file_prefix);

    /* Find a unique local filename. */
    while (mitm_handles[unused_handle].fd < 0) {
      mitm_handles[unused_handle].fd = open(file_path, O_CREAT | O_EXCL | O_NOATIME | O_NOFOLLOW | O_WRONLY, S_IRUSR | S_IWUSR);

      num_tries++;

      /* If open() failed, append "_X" to the file path, where X is an
       * incrementing integer. */
      if (mitm_handles[unused_handle].fd < 0) {
	snprintf(file_path, sizeof(file_path) - 1, "%s%s_%u", session_log_dir, file_prefix, num_tries);
      }
    }
    free(temp_name); temp_name = NULL;

    /* Get the base name of our log directory.  Because we're using GNU
     * basename(), we need to cut off the trailing slash, otherwise we get back
     * the empty string.
     *
     * "/home/ssh-mitm/sftp_session_0/" -> "sftp_session_0" */
    temp_name = xstrdup(session_log_dir);
    if (strlen(temp_name) > 0)
      temp_name[strlen(temp_name) - 1] = '\0';
    log_dir = basename(temp_name);

    /* Get the basename of the file we wrote.
     * "/home/ssh-mitm/sftp_session_0/lol.txt" -> "lol.txt" */
    file_prefix = basename(file_path);
    actual_path_len = strlen(log_dir) + 1 + strlen(file_prefix) + 1;
    mitm_handles[unused_handle].actual_path = calloc(actual_path_len, sizeof(char));

    /* Create the relative path, i.e.: "sftp_session_0/lol.txt". */
    r = snprintf(mitm_handles[unused_handle].actual_path, actual_path_len, "%s/%s", log_dir, file_prefix);
    xss_sanitize(mitm_handles[unused_handle].actual_path, r);

    free(temp_name); temp_name = NULL;
  }
}

/* Write discovered data to our local file.  We do this for both remote server
 * reads and writes. */
void mitm_handle_read_write(char *handle_str, size_t handle_len, u_int64_t offset, u_char *buf, size_t buf_len) {
  MITMHandle *mh = NULL;

  if ((mh = mitm_handle_search(handle_str, handle_len)) != NULL) {
    lseek(mh->fd, offset, SEEK_SET);
    write(mh->fd, buf, buf_len);
  } else
    logit(CANT_FIND_HANDLE, __func__);
}

/* Close the local file descriptor associated with this remote server handle.
 * Frees the slot this handle is in. */
void mitm_handle_close(const char *handle_str, size_t handle_len) {
  MITMHandle *mh = NULL;

  if ((mh = mitm_handle_search(handle_str, handle_len)) != NULL) {
    close(mh->fd);
    mitm_handle_free(mh);
  } else
    logit(CANT_FIND_HANDLE, __func__);
}

/* Searches for an MITMHandle, given its remote server handle and length.
 * Returns a pointer to it on success, or NULL if it could not be found. */
MITMHandle *mitm_handle_search(const char *handle_str, size_t handle_len) {
  u_int i = 0;

  for (i = 0; i < num_mitm_handles; i++) {
    if ((mitm_handles[i].in_use == 1) && (mitm_handles[i].handle_len == handle_len) && (memcmp(mitm_handles[i].handle_str, handle_str, handle_len) == 0)) {
      return &mitm_handles[i];
    }
  }
  return NULL;
}


/*
static void handle_unused(int i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

static int
handle_new(int use, const char *name, int fd, int flags, DIR *dirp)
{
	int i;

	if (first_unused_handle == -1) {
		if (num_handles + 1 <= num_handles)
			return -1;
		num_handles++;
		handles = xreallocarray(handles, num_handles, sizeof(Handle));
		handle_unused(num_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	return i;
}
*/

static int
handle_is_ok(int i, int type)
{
	return i >= 0 && (u_int)i < num_handles && handles[i].use == type;
}

/*
static int
handle_to_string(int handle, u_char **stringp, int *hlenp)
{
	if (stringp == NULL || hlenp == NULL)
		return -1;
	*stringp = xmalloc(sizeof(int32_t));
	put_u32(*stringp, handle);
	*hlenp = sizeof(int32_t);
	return 0;
}
*/

static int
handle_from_string(const u_char *handle, u_int hlen)
{
	int val;

	if (hlen != sizeof(int32_t))
		return -1;
	val = get_u32(handle);
	if (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		return val;
	return -1;
}

static char *
handle_to_name(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].name;
	return NULL;
}

/*
static DIR *
handle_to_dir(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR))
		return handles[handle].dirp;
	return NULL;
}

static int
handle_to_fd(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].fd;
	return -1;
}

static int
handle_to_flags(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].flags;
	return 0;
}

static void
handle_update_read(int handle, ssize_t bytes)
{
	if (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

static void
handle_update_write(int handle, ssize_t bytes)
{
	if (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}
*/

static u_int64_t
handle_bytes_read(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return (handles[handle].bytes_read);
	return 0;
}

static u_int64_t
handle_bytes_write(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return (handles[handle].bytes_write);
	return 0;
}

/*
static int
handle_close(int handle)
{
	int ret = -1;

	if (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		free(handles[handle].name);
		handle_unused(handle);
	} else if (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		free(handles[handle].name);
		handle_unused(handle);
	} else {
		errno = ENOENT;
	}
	return ret;
}
*/

static void
handle_log_close(int handle, char *emsg)
{
	if (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} else {
		logit("%s%sclosedir \"%s\"",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle));
	}
}

static void
handle_log_exit(void)
{
	u_int i;

	for (i = 0; i < num_handles; i++)
		if (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

/*
static int
get_handle(struct sshbuf *queue, int *hp)
{
	u_char *handle;
	int r;
	size_t hlen;

	*hp = -1;
	if ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		return r;
	if (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	free(handle);
	return 0;
}
*/

/* Handle return value must be free()'ed. */
int
get_handle_all(struct sshbuf *queue, u_char **handle_str, size_t *handle_len, int *handle_int)
{
	int r;

	if ((r = sshbuf_get_string(queue, handle_str, handle_len)) != 0)
	  return r;

	if (*handle_len < 256)
		*handle_int = handle_from_string(*handle_str, *handle_len);
	else {
		free(*handle_str); *handle_str = NULL;
		*handle_len = 0;
		*handle_int = -1;
		return -1;
	}

	return 0;
}

/* send replies */

static void
send_msg(struct sshbuf *m)
{
	int r;

	if ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_reset(m);
}

static const char *
status_to_message(u_int32_t status)
{
	const char *status_messages[] = {
		"Success",			/* SSH_FX_OK */
		"End of file",			/* SSH_FX_EOF */
		"No such file",			/* SSH_FX_NO_SUCH_FILE */
		"Permission denied",		/* SSH_FX_PERMISSION_DENIED */
		"Failure",			/* SSH_FX_FAILURE */
		"Bad message",			/* SSH_FX_BAD_MESSAGE */
		"No connection",		/* SSH_FX_NO_CONNECTION */
		"Connection lost",		/* SSH_FX_CONNECTION_LOST */
		"Operation unsupported",	/* SSH_FX_OP_UNSUPPORTED */
		"Unknown error"			/* Others */
	};
	return (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

static void
send_status(u_int32_t id, u_int32_t status)
{
	struct sshbuf *msg;
	int r;

	debug3("request %u: sent status %u", id, status);
	if (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (version >= 3) {
		if ((r = sshbuf_put_cstring(msg,
		    status_to_message(status))) != 0 ||
		    (r = sshbuf_put_cstring(msg, "")) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	send_msg(msg);
	sshbuf_free(msg);
}
static void
send_data_or_handle(char type, u_int32_t id, const u_char *data, int dlen)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_data(u_int32_t id, const u_char *data, int dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

/*
static void
send_handle(u_int32_t id, int handle)
{
	u_char *string;
	int hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	free(string);
}
*/

static void
send_handle_str(u_int32_t id, u_char *handle, size_t handle_len)
{
	debug("request %u: sent handle_str handle %d", id, atoi(handle));
	send_data_or_handle(SSH2_FXP_HANDLE, id, handle, handle_len);
}


static void
send_names(u_int32_t id, int count, const Stat *stats)
{
	struct sshbuf *msg;
	int i, r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, count)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	debug("request %u: sent names count %d", id, count);
	for (i = 0; i < count; i++) {
		if ((r = sshbuf_put_cstring(msg, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(msg, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(msg, &stats[i].attrib)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_attrib(u_int32_t id, const Attrib *a)
{
	struct sshbuf *msg;
	int r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_statvfs(u_int32_t id, struct statvfs *st)
{
	struct sshbuf *msg;
	u_int64_t flag;
	int r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(msg, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(msg, flag)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_namemax)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	send_msg(msg);
	sshbuf_free(msg);
}

/* parse incoming */

static void
process_init(void)
{
	struct sshbuf *msg;
	int r;

	if ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	verbose("received client version %u", version);
	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FILEXFER_VERSION)) != 0 ||
	    /* POSIX rename extension */
	    (r = sshbuf_put_cstring(msg, "posix-rename@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "1")) != 0 || /* version */
	    /* statvfs extension */
	    (r = sshbuf_put_cstring(msg, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "2")) != 0 || /* version */
	    /* fstatvfs extension */
	    (r = sshbuf_put_cstring(msg, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "2")) != 0 || /* version */
	    /* hardlink extension */
	    (r = sshbuf_put_cstring(msg, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "1")) != 0 || /* version */
	    /* fsync extension */
	    (r = sshbuf_put_cstring(msg, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "1")) != 0) /* version */
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	send_msg(msg);
	sshbuf_free(msg);
}

static void
process_open(u_int32_t id)
{
	u_int32_t pflags;
	Attrib a;
	char *name;
	u_char *handle_str = NULL;
	size_t handle_len = 0;
	u_int status = 0;
	int r;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: open \"%s\" flags %d", id, name, pflags);
	/*
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	if (readonly &&
	    ((flags & O_ACCMODE) == O_WRONLY ||
	    (flags & O_ACCMODE) == O_RDWR)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} else {
		fd = open(name, flags, mode);
		if (fd < 0) {
			status = errno_to_portable(errno);
		} else {
			handle = handle_new(HANDLE_FILE, name, fd, flags, NULL);
			if (handle < 0) {
				close(fd);
			} else {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	*/
	handle_str = mitm_do_open(client_conn, name, pflags, &a, &handle_len, &status);
	if (handle_str != NULL) {
		debug3("request %u: open \"%s\" returning handle: %d", id, name, handle_from_string(handle_str, handle_len));
		send_handle_str(id, handle_str, handle_len);
		mitm_handle_new(MITM_HANDLE_TYPE_FILE, name, pflags, handle_str, handle_len);
	} else {
		send_status(id, status);
		sftp_log(status, "open \"%s\" (Flags: %s)", name, string_from_portable(pflags));
	}

	free(handle_str);  handle_str = NULL;
	free(name);
}

static void
process_close(u_int32_t id)
{
	/*
	int r, handle, ret, status = SSH2_FX_FAILURE;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, NULL);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	*/
	int r;
	u_char *handle_str = NULL;
	size_t handle_len = 0;
	int handle_int = -1;
	int status;

	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	debug3("request %u: close handle %u", id, handle_int);
	status = mitm_do_close(client_conn, handle_str, handle_len);
	send_status(id, status);

	sftp_log_close(status, handle_str, handle_len);
	mitm_handle_close(handle_str, handle_len);
	free(handle_str); handle_str = NULL;
}

static void
process_read(u_int32_t id)
{
	/*
	u_char buf[64*1024];
	u_int32_t len;
	int r, handle, fd, ret, status = SSH2_FX_FAILURE;
	u_int64_t off;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug("request %u: read \"%s\" (handle %d) off %llu len %d",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	if (len > sizeof buf) {
		len = sizeof buf;
		debug2("read change len %d", len);
	}
	fd = handle_to_fd(handle);
	if (fd >= 0) {
		if (lseek(fd, off, SEEK_SET) < 0) {
			error("process_read: seek failed");
			status = errno_to_portable(errno);
		} else {
			ret = read(fd, buf, len);
			if (ret < 0) {
				status = errno_to_portable(errno);
			} else if (ret == 0) {
				status = SSH2_FX_EOF;
			} else {
				send_data(id, buf, ret);
				status = SSH2_FX_OK;
				handle_update_read(handle, ret);
			}
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	*/
	int r;
	u_char *handle_str = NULL;
	size_t handle_len = 0;
	int handle_int = -1;
	u_int32_t read_len;
	u_int64_t offset;
	u_int status = 0;
	u_char *buf = NULL;
	size_t buf_len = 0;

	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &offset)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &read_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: read (handle %d) off %llu len %d",
	    id, handle_int, (unsigned long long)offset, read_len);
	buf = mitm_do_read(client_conn, handle_str, handle_len, offset, read_len, &buf_len, &status);
	if (buf != NULL) {
		send_data(id, buf, buf_len);
		mitm_handle_read_write(handle_str, handle_len, offset, buf, buf_len);
	} else
		send_status(id, status);

	free(buf); buf = NULL;
	free(handle_str); handle_str = NULL;
}

static void
process_write(u_int32_t id)
{
	/*
	u_int64_t off;
	size_t len;
	int r, handle, fd, ret, status;
	u_char *data;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	if (fd < 0)
		status = SSH2_FX_FAILURE;
	else {
		if (!(handle_to_flags(handle) & O_APPEND) &&
				lseek(fd, off, SEEK_SET) < 0) {
			status = errno_to_portable(errno);
			error("process_write: seek failed");
		} else {
	*/
/* XXX ATOMICIO ? */
	/*
			ret = write(fd, data, len);
			if (ret < 0) {
				error("process_write: write failed");
				status = errno_to_portable(errno);
			} else if ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} else {
				debug2("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	free(data);
	*/
	int r;
	u_char *handle_str = NULL;
	size_t handle_len = 0;
	int handle_int = -1;
	u_int64_t offset;
	u_int status;
	u_char *buf = NULL;
	size_t buf_len = 0;

	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &offset)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &buf, &buf_len)) != 0)

		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	debug3("request %u: write (handle %d) off %llu len %zu",
	    id, handle_int, (unsigned long long)offset, buf_len);
	status = mitm_do_write(client_conn, handle_str, handle_len, offset, buf, buf_len);
	mitm_handle_read_write(handle_str, handle_len, offset, buf, buf_len);
	send_status(id, status);

	free(handle_str); handle_str = NULL;
	free(buf); buf = NULL;
}

static void
process_do_stat(u_int32_t id, int do_lstat_arg)
{
	char *name;
	int r, status = SSH2_FX_FAILURE;
	Attrib *b;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: %sstat", id, do_lstat_arg ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat_arg ? "l" : "", name);
	/*
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	if (r < 0) {
		status = errno_to_portable(errno);
	} else {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	*/
	if (do_lstat_arg) 
		b = do_lstat(client_conn, name, 0, &status);
	else
		b = do_stat(client_conn, name, 0, &status);

	if (b != NULL)
		send_attrib(id, b);
	else
		send_status(id, status);

	sftp_log_attrib(do_lstat_arg ? "lstat" : "stat", status, name, b);
	free(name);
}

static void
process_stat(u_int32_t id)
{
	process_do_stat(id, 0);
}

static void
process_lstat(u_int32_t id)
{
	process_do_stat(id, 1);
}

static void
process_fstat(u_int32_t id)
{
	Attrib *a;
	int status = SSH2_FX_FAILURE;
	u_char *handle_str = NULL;
	size_t handle_len = 0;
	int handle_int = -1;
	int r;

	/*
	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	if (fd >= 0) {
		r = fstat(fd, &st);
		if (r < 0) {
			status = errno_to_portable(errno);
		} else {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	*/
	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: fstat (handle %u)", id, handle_int);
	a = mitm_do_fstat(client_conn, handle_str, handle_len, 1, &status);
	if (a != NULL)
		send_attrib(id, a);
	else
		send_status(id, status);

	sftp_log_handle_attrib("fstat", status, handle_str, handle_len, a);
	free(handle_str);  handle_str = NULL;
}

/*
static struct timeval *
attrib_to_tv(const Attrib *a)
{
	static struct timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	return tv;
}
*/

static void
process_setstat(u_int32_t id)
{
	Attrib a;
	char *name;
	int r, status = SSH2_FX_OK;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: setstat name \"%s\"", id, name);
	/*
	if (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		if (r == -1)
			status = errno_to_portable(errno);
	}
	if (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		if (r == -1)
			status = errno_to_portable(errno);
	}
	if (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		char buf[64];
		time_t t = a.mtime;

		strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		if (r == -1)
			status = errno_to_portable(errno);
	}
	if (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		if (r == -1)
			status = errno_to_portable(errno);
	}
	*/
	status = mitm_do_setstat(client_conn, name, &a);
	send_status(id, status);

	sftp_log_attrib("setstat", status, name, &a);
	free(name);
}

static void
process_fsetstat(u_int32_t id)
{
	Attrib a;
	int status = SSH2_FX_OK;
	u_char *handle_str = NULL;
	size_t handle_len = 0;
	int handle_int = -1;
	int r;

	/*
	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	if (fd < 0)
		status = SSH2_FX_FAILURE;
	else {
		char *name = handle_to_name(handle);

		if (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			if (r == -1)
				status = errno_to_portable(errno);
		}
		if (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#else
			r = chmod(name, a.perm & 07777);
#endif
			if (r == -1)
				status = errno_to_portable(errno);
		}
		if (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			char buf[64];
			time_t t = a.mtime;

			strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#else
			r = utimes(name, attrib_to_tv(&a));
#endif
			if (r == -1)
				status = errno_to_portable(errno);
		}
		if (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#else
			r = chown(name, a.uid, a.gid);
#endif
			if (r == -1)
				status = errno_to_portable(errno);
		}
	}
	*/
	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: fsetstat handle %d", id, handle_int);
	status = mitm_do_fsetstat(client_conn, handle_str, handle_len, &a);
	send_status(id, status);

	sftp_log_handle_attrib("fsetstat", status, handle_str, handle_len, &a);
	free(handle_str);  handle_str = NULL;
}

static void
process_opendir(u_int32_t id)
{
	/*
	DIR *dirp = NULL;
	char *path;
	int r, handle, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	if (dirp == NULL) {
		status = errno_to_portable(errno);
	} else {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		if (handle < 0) {
			closedir(dirp);
		} else {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	*/
	int r, status = SSH2_FX_FAILURE;
	char *path;
	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug("request %u: opendir \"%s\"", id, path);

	size_t handle_len = 0;
	u_char *handle_str = mitm_do_opendir(client_conn, path, &handle_len, &status);
	if (handle_str != NULL) {
		debug("request %u: opendir \"%s\" returning handle: %u", id, path, handle_from_string(handle_str, handle_len));
		send_handle_str(id, handle_str, handle_len);
		mitm_handle_new(MITM_HANDLE_TYPE_DIR, path, 0, handle_str, handle_len);
	} else
		send_status(id, status);

	free(handle_str);  handle_str = NULL;
	free(path);
}

static void
process_readdir(u_int32_t id)
{
	/*
	DIR *dirp;
	struct dirent *dp;
	char *path;
	int r, handle;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	if (dirp == NULL || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} else {
		struct stat st;
		char pathname[PATH_MAX];
		Stat *stats;
		int nstats = 10, count = 0, i;

		stats = xcalloc(nstats, sizeof(Stat));
		while ((dp = readdir(dirp)) != NULL) {
			if (count >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, sizeof(Stat));
			}
	*/
/* XXX OVERFLOW ? */
	/*
			snprintf(pathname, sizeof pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			if (lstat(pathname, &st) < 0)
				continue;
			stat_to_attrib(&st, &(stats[count].attrib));
			stats[count].name = xstrdup(dp->d_name);
			stats[count].long_name = ls_file(dp->d_name, &st, 0, 0);
			count++;
	*/
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
	/*
			if (count == 100)
				break;
		}
		if (count > 0) {
			send_names(id, count, stats);
			for (i = 0; i < count; i++) {
				free(stats[i].name);
				free(stats[i].long_name);
			}
		} else {
			send_status(id, SSH2_FX_EOF);
		}
		free(stats);
	}
	*/
	u_char *handle_str = NULL;
	size_t handle_len = 0;
	int handle_int = -1;
	int r;
	int status = 0;
	u_int count = 0, i = 0;
	Stat *stats;

	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0)
		fatal("%s: buffer error", __func__);

	debug("request %u: readdir(handle %d)", id, handle_int);
	stats = mitm_do_readdir(client_conn, id, handle_str, handle_len, &count, &status);
	if (stats == NULL)
		send_status(id, status);
	else {
		send_names(id, count, stats);
		for (i = 0; i < count; i++) {
			sftp_log_readdir(handle_str, handle_len, stats[i].long_name);
			free(stats[i].name); stats[i].name = NULL;
			free(stats[i].long_name); stats[i].long_name = NULL;
		}
		free(stats); stats = NULL;
	}
	free(handle_str); handle_str = NULL;
}

static void
process_remove(u_int32_t id)
{
	char *name;
	int r, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	/*
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	*/
	status = mitm_do_rm(client_conn, name);
	send_status(id, status);

	sftp_log(status, "rm \"%s\"", name);
	free(name);
}

static void
process_mkdir(u_int32_t id)
{
	Attrib a;
	char *name;
	int r, mode, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	/*
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	*/
	status = mitm_do_mkdir(client_conn, name, &a);
	send_status(id, status);

	sftp_log(status, "mkdir \"%s\" (mode: 0%o)", name, mode);
	free(name);
}

static void
process_rmdir(u_int32_t id)
{
	char *name;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	/*
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	*/
	status = mitm_do_rmdir(client_conn, name);
	send_status(id, status);

	sftp_log(status, "rmdir \"%s\"", name);
	free(name);
}

static void
process_realpath(u_int32_t id)
{
	char *path;
	int r;
	char *realpath;
	Stat s;
	u_int status;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if (path[0] == '\0') {
		free(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	/*
	if (realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
	} else {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	*/
	realpath = do_realpath(client_conn, path, &status);
	if (status == SSH2_FX_OK) {
	  attrib_clear(&s.attrib);
	  s.name = s.long_name = realpath;
	  send_names(id, 1, &s);
	} else
	  send_status(id, status);

	sftp_log(status, "realpath \"%s\" (Result: %s)", path, realpath != NULL ? realpath : "(NULL)");
	free(realpath); realpath = NULL;
	free(path);
}

static void
process_rename(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	/*
	status = SSH2_FX_FAILURE;
	if (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	else if (S_ISREG(sb.st_mode)) {
	*/
		/* Race-free rename of regular files */
	/*
		if (link(oldpath, newpath) == -1) {
			if (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				struct stat st;

	*/
				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
	/*
				if (stat(newpath, &st) == -1) {
					if (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					else
						status = SSH2_FX_OK;
				}
			} else {
				status = errno_to_portable(errno);
			}
		} else if (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
	*/
			/* clean spare link */
	/*
			unlink(newpath);
		} else
			status = SSH2_FX_OK;
	} else if (stat(newpath, &sb) == -1) {
		if (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		else
			status = SSH2_FX_OK;
	}
	*/
	status = mitm_do_rename(client_conn, oldpath, newpath, 1);
	send_status(id, status);

	sftp_log(status, "rename \"%s\" \"%s\"", oldpath, newpath);
	free(oldpath);
	free(newpath);
}

static void
process_readlink(u_int32_t id)
{
	int r;
	char *path;
	u_int status = 0;
	char *filename = NULL, *long_name = NULL;
	Attrib a;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	/*
	if ((len = readlink(path, buf, sizeof(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	else {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	*/
	if (mitm_do_readlink(client_conn, path, &status, &filename, &long_name, &a) == 1) {
		Stat s;
		s.name = filename;
		s.long_name = long_name;
		s.attrib = a;
		send_names(id, 1, &s);
	} else
		send_status(id, status);

	sftp_log_attrib("readlink", status, path, &a);
	free(filename); filename = NULL;
	free(long_name); long_name = NULL;
	free(path);
}

static void
process_symlink(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	/*
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	*/
	status = mitm_do_symlink(client_conn, oldpath, newpath);
	send_status(id, status);

	sftp_log(status, "ln -s \"%s\" \"%s\"", oldpath, newpath);
	free(oldpath);
	free(newpath);
}

static void
process_extended_posix_rename(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	/*
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	*/
	status = mitm_do_rename(client_conn, oldpath, newpath, 0);
	send_status(id, status);

	sftp_log(status, "posix_rename \"%s\" \"%s\"", oldpath, newpath);
	free(oldpath);
	free(newpath);
}

static void
process_extended_statvfs(u_int32_t id)
{
	char *path;
	struct statvfs st;
	int r;
	u_int status = 0;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	/*
	if (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	else
		send_statvfs(id, &st);
	*/
	if (mitm_do_statvfs(client_conn, path, &st, &status) != -1)
		send_statvfs(id, &st);
	else
		send_status(id, status);

	sftp_log_statvfs(status, path, &st);
        free(path);
}

static void
process_extended_fstatvfs(u_int32_t id)
{
	int r, handle_int;
	struct statvfs st;
	u_int status = 0;
	u_char *handle_str = NULL;
	size_t handle_len = 0;

	/*
	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		return;
	}
	if (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	else
		send_statvfs(id, &st);
	*/

	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: fstatvfs (handle %u)", id, handle_int);
	if (mitm_do_fstatvfs(client_conn, handle_str, handle_len, &st, &status) != -1)
		send_statvfs(id, &st);
	else
		send_status(id, status);

	sftp_log_fstatvfs(status, handle_str, handle_len, &st);
	free(handle_str); handle_str = NULL;
}

static void
process_extended_hardlink(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	/*
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	*/
	status = mitm_do_hardlink(client_conn, oldpath, newpath);
	send_status(id, status);

	sftp_log(status, "ln \"%s\" \"%s\"", oldpath, newpath);
	free(oldpath);
	free(newpath);
}

static void
process_extended_fsync(u_int32_t id)
{
	int handle_int, r, status = SSH2_FX_OP_UNSUPPORTED;
	u_char *handle_str = NULL;
	size_t handle_len = 0;

	/*
	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	*/
	if ((r = get_handle_all(iqueue, &handle_str, &handle_len, &handle_int)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("request %u: fsync (handle %u)", id, handle_int);
	/*
	if ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	else if (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	*/
	status = mitm_do_fsync(client_conn, handle_str, handle_len);
	send_status(id, status);

	sftp_log_fsync(status, handle_str, handle_len);
	free(handle_str); handle_str = NULL;
}

static void
process_extended(u_int32_t id)
{
	char *request;
	int i, r;

	if ((r = sshbuf_get_cstring(iqueue, &request, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	for (i = 0; extended_handlers[i].handler != NULL; i++) {
		if (strcmp(request, extended_handlers[i].ext_name) == 0) {
			if (!request_permitted(&extended_handlers[i]))
				send_status(id, SSH2_FX_PERMISSION_DENIED);
			else
				extended_handlers[i].handler(id);
			break;
		}
	}
	if (extended_handlers[i].handler == NULL) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	}
	free(request);
}

/* stolen from ssh-agent */

static void
process(void)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	const u_char *cp;
	int i, r;
	u_int32_t id;

	buf_len = sshbuf_len(iqueue);
	if (buf_len < 5)
		return;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	if (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	if (buf_len < msg_len + 4)
		return;
	if ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	buf_len -= 4;
	if ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	switch (type) {
	case SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		break;
	case SSH2_FXP_EXTENDED:
		if (!init_done)
			fatal("Received extended request before init");
		if ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		process_extended(id);
		break;
	default:
		if (!init_done)
			fatal("Received %u request before init", type);
		if ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		for (i = 0; handlers[i].handler != NULL; i++) {
			if (type == handlers[i].type) {
				if (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} else {
					handlers[i].handler(id);
				}
				break;
			}
		}
		if (handlers[i].handler == NULL)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	if (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	if (msg_len < consumed) {
		error("msg_len %u < consumed %u", msg_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	if (msg_len > consumed &&
	    (r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

/* Cleanup handler that logs active handles upon normal exit */
void
sftp_server_cleanup_exit(int i)
{
	write(session_log_fd, "</pre></html>", 13);
	fdatasync(session_log_fd);
	close(session_log_fd);

	if (pw != NULL && client_addr != NULL) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

static void
sftp_server_usage(void)
{
	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P blacklisted_requests] "
	    "[-p whitelisted_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    "/usr/libexec/sftp-server", "/usr/libexec/sftp-server");
	exit(1);
}

int
sftp_server_main(int argc, char **argv, struct passwd *user_pw, char *original_host, unsigned short original_port, char *username, char *password_and_fingerprint_socket_name, char *log_filepath, char *log_dir)
{
	fd_set *rset, *wset;
	int i, r, in, out, max, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen, set_size;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	char *cp, *homedir = NULL, buf[4*4096];
	long mask;

	extern char *optarg;
	extern char *__progname;

	ssh_malloc_init();	/* must be called before any mallocs */
	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	while (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		switch (ch) {
		case 'Q':
			if (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			for (i = 0; handlers[i].handler != NULL; i++)
				printf("%s\n", handlers[i].name);
			for (i = 0; extended_handlers[i].handler != NULL; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			break;
		case 'R':
			readonly = 1;
			break;
		case 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			break;
		case 'e':
			log_stderr = 1;
			break;
		case 'l':
			log_level = log_level_number(optarg);
			if (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			break;
		case 'f':
			log_facility = log_facility_number(optarg);
			if (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			break;
		case 'd':
			/*
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, (char *)NULL);
			free(cp);
			*/
			break;
		case 'p':
			if (request_whitelist != NULL)
				fatal("Permitted requests already set");
			request_whitelist = xstrdup(optarg);
			break;
		case 'P':
			if (request_blacklist != NULL)
				fatal("Refused requests already set");
			request_blacklist = xstrdup(optarg);
			break;
		case 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			if (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(void)umask((mode_t)mask);
			break;
		case 'h':
		default:
			sftp_server_usage();
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);
	mitm_init_log(log_filepath, log_dir);

	/*
	 * On platforms where we can, avoid making /proc/self/{mem,maps}
	 * available to the user so that sftp access doesn't automatically
	 * imply arbitrary code execution access that will break
	 * restricted configurations.
	 */
	platform_disable_tracing(1);	/* strict */

	/* Drop any fine-grained privileges we don't need */
	platform_pledge_sftp_server();

	if ((cp = getenv("SSH_CONNECTION")) != NULL) {
		client_addr = xstrdup(cp);
		if ((cp = strchr(client_addr, ' ')) == NULL) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} else
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_BINARY);
	setmode(out, O_BINARY);
#endif

	max = 0;
	if (in > max)
		max = in;
	if (out > max)
		max = out;

	if ((iqueue = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((oqueue = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	rset = xcalloc(howmany(max + 1, NFDBITS), sizeof(fd_mask));
	wset = xcalloc(howmany(max + 1, NFDBITS), sizeof(fd_mask));

	if (homedir != NULL) {
		if (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	client_conn = make_connection(original_host, original_port, username, password_and_fingerprint_socket_name);
	set_size = howmany(max + 1, NFDBITS) * sizeof(fd_mask);
	for (;;) {
		memset(rset, 0, set_size);
		memset(wset, 0, set_size);

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		if ((r = sshbuf_check_reserve(iqueue, sizeof(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_MSG_LENGTH)) == 0)
			FD_SET(in, rset);
		else if (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal("%s: sshbuf_check_reserve failed: %s",
			    __func__, ssh_err(r));

		olen = sshbuf_len(oqueue);
		if (olen > 0)
			FD_SET(out, wset);

		if (select(max+1, rset, wset, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			error("select: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		if (FD_ISSET(in, rset)) {
			len = read(in, buf, sizeof buf);
			if (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} else if (len < 0) {
				error("read: %s", strerror(errno));
				sftp_server_cleanup_exit(1);
			} else if ((r = sshbuf_put(iqueue, buf, len)) != 0) {
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			}
		}
		/* send oqueue to stdout */
		if (FD_ISSET(out, wset)) {
			len = write(out, sshbuf_ptr(oqueue), olen);
			if (len < 0) {
				error("write: %s", strerror(errno));
				sftp_server_cleanup_exit(1);
			} else if ((r = sshbuf_consume(oqueue, len)) != 0) {
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			}
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_MSG_LENGTH);
		if (r == 0)
			process();
		else if (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal("%s: sshbuf_check_reserve: %s",
			    __func__, ssh_err(r));
	}
}

/* Copied from sftp.c. */
/* ARGSUSED */
static void
killchild(int signo)
{
	if (sshpid > 1) {
		kill(sshpid, SIGTERM);
		waitpid(sshpid, NULL, 0);
	}

	_exit(1);
}

/* Copied from sftp.c. */
/* ARGSUSED */
static void
suspchild(int signo)
{
	if (sshpid > 1) {
		kill(sshpid, signo);
		while (waitpid(sshpid, NULL, WUNTRACED) == -1 && errno == EINTR)
			continue;
	}
	kill(getpid(), SIGSTOP);
}

/* Copied from sftp.c. */
static void
connect_to_server(char *path, char **args, int *in, int *out)
{
	int c_in, c_out;

#ifdef USE_PIPES
	int pin[2], pout[2];

	if ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#else /* USE_PIPES */
	int inout[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */

	if ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	else if (sshpid == 0) {
		if ((dup2(c_in, STDIN_FILENO) == -1) ||
		    (dup2(c_out, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*in);
		close(*out);
		close(c_in);
		close(c_out);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		signal(SIGINT, SIG_IGN);
		signal(SIGTERM, SIG_DFL);

		execvp(path, args);
		fprintf(stderr, "exec: %s: %s\n", path, strerror(errno));
		_exit(1);
	}

	signal(SIGTERM, killchild);
	signal(SIGINT, killchild);
	signal(SIGHUP, killchild);
	signal(SIGTSTP, suspchild);
	signal(SIGTTIN, suspchild);
	signal(SIGTTOU, suspchild);
	close(c_in);
	close(c_out);
}

void mitm_init_log(char *log_filepath, char *log_dir) {
  session_log_fd = open(log_filepath, O_NOATIME | O_NOFOLLOW | O_WRONLY
#ifdef SYNC_LOG
        | O_SYNC
#endif
        );

  /* Ensure that writes append to the log, since its initialized with
   * connection information. */
  lseek(session_log_fd, 0, SEEK_END);

  if (session_log_fd < 0)
    logit("MITM: failed to open SFTP log: %s", log_filepath);

  session_log_dir = strdup(log_dir);
  if ((session_log_dir = xstrdup(log_dir)) == NULL)
    fatal("Failed to allocate memory for session log dir path.");
}

struct sftp_conn *
make_connection(char *host, unsigned short port, char *username, char *password_and_fingerprint_socket_name) {
	arglist args;
	char *ssh_program = MITM_SSH_CLIENT;
	int in = -1, out = -1;

	args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-E");
	addargs(&args, "%s", MITM_SSH_CLIENT_LOG);
	addargs(&args, "-F");
	addargs(&args, "%s", MITM_SSH_CLIENT_CONFIG);
	addargs(&args, "-Z");
	addargs(&args, "%s", password_and_fingerprint_socket_name);
	addargs(&args, "-oForwardX11=no");
	addargs(&args, "-oForwardAgent=no");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oPort=%u", port);
	addargs(&args, "-oProtocol=2");
	addargs(&args, "-s");
	addargs(&args, "--");
	addargs(&args, "%s@%s", username, host);
	addargs(&args, "sftp");
	connect_to_server(ssh_program, args.list, &in, &out);
	return do_init(in, out, 32768, 64, 0);
}

/* Simple XSS sanitization. */
void xss_sanitize(char *buf, int buf_len) {
  int i;
  for (i = 0; i < buf_len; i++) {
    if (buf[i] == '<')
      buf[i] = '[';
    else if (buf[i] == '>')
      buf[i] = ']';
  }
}

/* C doesn't let you pass variable-length arguments from one function to
 * another if the second function needs to call va_start() again.  These
 * defines cut down on duplicate code in that case.  Not sure if there's any
 * other way to do it... */
#define SFTP_LOG_HEADER() va_start(args, fmt); \
\
  /* By setting the last byte to NULL and giving sizeof(buf) - 1 to vsnprintf, \
   * we can be sure that the buffer will be NULL-terminated afterwards. */ \
  buf[sizeof(buf) - 1] = '\0'; \
\
  ret = vsnprintf(buf, buf_len - 1, fmt, args); \
\
  /* If we need a larger buffer to format the string into... */ \
  if (ret >= buf_len) { \
    buf_len = ret + 1; \
    if ((buf = reallocarray(NULL, buf_len, sizeof(char))) == NULL) \
      fatal("Could not allocate buffer for sftp_log."); \
    buf[buf_len - 1] = '\0'; \
\
    va_end(args); \
    va_start(args, fmt); \
    ret = vsnprintf(buf, buf_len, fmt, args); \
  }

#define SFTP_LOG_FOOTER() va_end(args); \
  /* Free the buffer, if we allocated it. */ \
  if (buf != buf_stack) { \
    free(buf); buf = NULL; \
  }

/* Log an SFTP command. */
void sftp_log(u_int status, const char *fmt, ...) {
  char buf_stack[512], *buf = buf_stack;
  int buf_len = sizeof(buf_stack), ret = 0;
  va_list args;

  SFTP_LOG_HEADER()
  _sftp_log(status, 1, buf, ret);
  SFTP_LOG_FOOTER()
}

/* Log an SFTP command without XSS filtering enabled.  Don't use this unless
 * you know what you're doing. */
void sftp_log_no_filter(u_int status, const char *fmt, ...) {
  char buf_stack[512], *buf = buf_stack;
  int buf_len = sizeof(buf_stack), ret = 0;
  va_list args;

  SFTP_LOG_HEADER()
  _sftp_log(status, 0, buf, ret);
  SFTP_LOG_FOOTER()
}

void _sftp_log(u_int status, u_int do_xss_filtering, char *buf, int buf_len) {
  write(session_log_fd, "> ", 2);

  /* Replace any angled brackets in the buffer. */
  if (do_xss_filtering)
    xss_sanitize(buf, buf_len);

  /* Write the buffer to the session log. */
  write(session_log_fd, buf, buf_len);

  /* If the status is not success, write it into the log as well. */
  if (status != SSH2_FX_OK) {
    char errmsg[64];
    const char *m = status_to_message(status);
    int r = 0;

    memset(errmsg, 0, sizeof(errmsg));

    r = snprintf(errmsg, sizeof(errmsg) - 1, " (Error: %s)", m);
    write(session_log_fd, errmsg, r);
  }

  write(session_log_fd, "\n", 1);
}

/* Log a file transfer or directory listing. */
void sftp_log_close(u_int status, char *handle_str, size_t handle_len) {
  MITMHandle *mh = NULL;

  if ((mh = mitm_handle_search(handle_str, handle_len)) != NULL) {
    char *original_path = mh->original_path;

    /* If a file handle was closed... */
    if (mh->type == MITM_HANDLE_TYPE_FILE) {
      u_int32_t pflags = mh->pflags;
      char *actual_path = mh->actual_path;
      const char get[] = "get";
      const char put[] = "put";
      const char getput[] = "get/put";
      const char *verb = getput;
      int read = 0, write = 0;

      /* Was the file open for reading, writing, or both? */
      read = (pflags & SSH2_FXF_READ);
      write = (pflags & SSH2_FXF_WRITE) || (pflags & SSH2_FXF_APPEND);

      if (read && !write)
	verb = get;
      else if (!read && write)
	verb = put;

      /* Make a link in the log to the local file we saved. */
      sftp_log_no_filter(status, "%s <a href=\"%s\">%s</a>", verb, actual_path, original_path);
    } else { /* ...a directory was closed. */
      sftp_log(status, "ls %s\n%s", original_path, mh->file_listing);
    }
  } else
    logit(CANT_FIND_HANDLE, __func__);
}

/* Writes an Attrib struct to the log. */
void sftp_log_attrib(const char *sftp_func, u_int status, char *name, Attrib *a) {
  if (a != NULL) {
    status = SSH2_FX_OK;
    sftp_log(status, "%s \"%s\" (Result: flags: %u; size: %lu; uid: %u; gid: %u; perm: 0%o, atime: %u, mtime: %u)", sftp_func, name, a->flags, a->size, a->uid, a->gid, a->perm, a->atime, a->mtime);
  } else
    sftp_log(status, "%s \"%s\" (Result: flags: ?; size: ?; uid: ?; gid: ?; perm: ?, atime: ?, mtime: ?)", sftp_func, name);
}

/* Given a handle, writes an Attrib struct to the log. */
void sftp_log_handle_attrib(const char *func, u_int status, char *handle_str, size_t handle_len, Attrib *a) {
  MITMHandle *mh = NULL;

  if ((mh = mitm_handle_search(handle_str, handle_len)) != NULL)
    sftp_log_attrib(func, status, mh->original_path, a);
  else
    logit(CANT_FIND_HANDLE, __func__);
}

/* Stores the result of a readdir() call (done during file listings). */
void sftp_log_readdir(char *handle_str, size_t handle_len, char *listing) {
  int resize_needed = 0;
  MITMHandle *mh = NULL;

  if ((mh = mitm_handle_search(handle_str, handle_len)) != NULL) {
    size_t listing_len = strlen(listing);

    /* If the file listing array hasn't been initialized yet, do that now. */
    if (mh->file_listing_size == 0) {
      mh->file_listing_size = MITM_HANDLES_FILE_LISTING_BLOCK;
      if ((mh->file_listing = reallocarray(NULL, mh->file_listing_size, sizeof(char))) == NULL)
	fatal("MITM: could not allocate file_listing!");
      mh->file_listing[0] = '\0';
    }

    /* If the array isn't big enough, resize it.  (+1 for the newline, and +1
     * for the NULL byte) */
    while (mh->file_listing_size < (strlen(mh->file_listing) + listing_len + 1 + 1)) {
      mh->file_listing_size += MITM_HANDLES_FILE_LISTING_BLOCK;
      resize_needed = 1;
    }

    if (resize_needed) {
      if((mh->file_listing = reallocarray(mh->file_listing, mh->file_listing_size, sizeof(char))) == NULL)
	fatal("MITM: could not allocate file_listing!");
    }

    strlcat(mh->file_listing, listing, mh->file_listing_size);
    strlcat(mh->file_listing, "\n", mh->file_listing_size);
  } else
    logit(CANT_FIND_HANDLE, __func__);
}

/* Writes a statvfs struct to the log. */
void sftp_log_statvfs(u_int status, char *path, struct statvfs *st) {
  sftp_log(status, "statvfs \"%s\" (Result: filesystem block size: %lu; fragment size: %lu; filesystem size [measured in fragments]: %lu; number of free blocks: %lu; number of free blocks for unprivileged users: %lu; number of inodes: %lu; number of free inodes: %lu; number of free inodes for unprivileged users: %lu; filesystem ID: %lu; mount flags: %lu; maximum filename length: %lu)", path, st->f_bsize, st->f_frsize, st->f_blocks, st->f_bfree, st->f_bavail, st->f_files, st->f_ffree, st->f_favail, st->f_fsid, st->f_flag, st->f_namemax);
}

/* Given a file handle, writes a statvfs struct to the log. */
void sftp_log_fstatvfs(u_int status, char *handle_str, size_t handle_len, struct statvfs *st) {
  MITMHandle *mh = NULL;

  if ((mh = mitm_handle_search(handle_str, handle_len)) != NULL)
    sftp_log_statvfs(status, mh->original_path, st);
  else
    logit(CANT_FIND_HANDLE, __func__);
}

/* Logs an fsync() call. */
void sftp_log_fsync(u_int status, char *handle_str, size_t handle_len) {
  MITMHandle *mh = NULL;

  if ((mh = mitm_handle_search(handle_str, handle_len)) != NULL)
    sftp_log(status, "fsync \"%s\"", mh->original_path);
  else
    logit(CANT_FIND_HANDLE, __func__);
}
