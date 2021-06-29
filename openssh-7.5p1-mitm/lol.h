#ifndef LOL_H
#define LOL_H

/* Current version of SSH MITM. */
#define SSH_MITM_VERSION "v2.3-dev"

/* Define these in order to force connections to a test host.
 * Useful for quickly testing changes without needing to ARP 
 * spoof; just connect to sshd's port directly. */

#define DEBUG_HOST "10.17.81.177"
#define DEBUG_PORT 22


/* This is the user account that all incoming connections will authenticate
 * as (the provided user name is ignored). */
#define UNPRIVED_MITM_USER "ssh-mitm"

/* The root path of SSH MITM (default: "/home/ssh-mitm/") */
#define MITM_ROOT "/home/" UNPRIVED_MITM_USER "/"

/* The log path of SSH MITM (default: "/home/ssh-mitm/log/") */
#define MITM_LOG "/home/" UNPRIVED_MITM_USER "/log/"

/* The path to the ssh client config. */
#define MITM_SSH_CLIENT_CONFIG MITM_ROOT "etc/ssh_config"

/* The path to the modified ssh client. */
#define MITM_SSH_CLIENT MITM_ROOT "bin/ssh"

/* The path to the client log file. The "ssh" and "sftp" clients' stderr
 * will go here. */
#define MITM_SSH_CLIENT_LOG MITM_LOG "client.log"

/* This is the size of the buffer used to write the password and read host key
 * fingerprints to/from the client program. */
#define SOCKET_PASSWORD_AND_FINGERPRINT_BUFFER_SIZE 1024

/* The size of the buffer used to store partial fingerprints intercepted. */
#define EXTRA_FP_BYTES_SIZE 64

/* The path to the docker program (for MITM'ing public key auth). */
#define DOCKER_CMD "/usr/bin/docker"

/* Uncomment this to open(2) log files with the O_SYNC flag.  Effectively, this
 * would cause logs to be written syncronously, though at the expense of lower
 * session responsiveness. */
/*#define SYNC_LOG 1*/

struct _Lol {
  char *original_host;
  unsigned short original_port;
  unsigned short keyauth_used;  /* Set to 1 if pubkey authentication was used. */
  char *username;
  char *password;
};
typedef struct _Lol Lol;

#define MAX_SERVER_HOSTKEY_FPS 8
struct _hostkey_fp {
  char *old;
  char *new;
};
typedef struct _hostkey_fp hostkey_fp;

#endif /* LOL_H */
