#!/usr/bin/env python3

"""
DockerSpawnifier.py
Copyright (C) 2021  Joe Testa <jtesta@positronsecurity.com>

This program is free software: you can redistribute it and/or modify
it under the terms version 3 of the GNU General Public License as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


Version: 1.0
Date:    July 1, 2021


This daemon runs Docker containers on behalf of sshd_mitm so that changes don't need to be made to its AppArmor profile that would significantly reduce its effectiveness.

This daemon routes stdin, stdout, and stderr to and from the Docker container and sshd_mitm via UNIX domain sockets.

Run with -v to enable verbose output.  Run with -t to test with DockerSpawnifier_Test_Client.py (this disables Docker's TTY output so it doesn't immediately terminate).
"""

import os
import select
import socket
import subprocess
import sys
import threading
import traceback


# Path and arguments to docker executable.  Note that SFTP requires no TTY flag.
DOCKER_CMD_SHELL = ['/usr/bin/docker', 'run', '-it', '--rm', 'ssh-mitm-fake-env']
DOCKER_CMD_SFTP = ['/usr/bin/docker', 'run', '-i', '--rm', 'ssh-mitm-fake-env', '/usr/lib/openssh/sftp-server']

# Command to launch the rootless daemon.
DOCKER_DAEMON = ['/bin/bash', '-c', '/usr/bin/dockerd-rootless.sh']

# Log for docker daemon stdout/stderr.
DOCKER_DAEMON_LOG = "/home/ssh-mitm/log/docker_daemon.log"

# Environment variables for the docker container.
DOCKER_CLIENT_ENV = {'DOCKER_HOST': 'unix:///home/ssh-mitm/.docker/run/docker.sock'}

# Environment variables for the docker daemon.
DOCKER_DAEMON_ENV = {'DOCKER_HOST': 'unix:///home/ssh-mitm/.docker/run/docker.sock', 'PATH': '/usr/bin:/usr/sbin', 'XDG_RUNTIME_DIR': '/home/ssh-mitm/.docker/run', 'HOME': '/home/ssh-mitm'}

# Directory to create UNIX sockets in, for communication with sshd_mitm.
SOCKET_DIR = '/home/ssh-mitm/tmp/'

# The name of the master socket used by sshd_mitm to request the launch of a new container.
MASTER_SOCKET_PATH = os.path.join(SOCKET_DIR, 'dockerspawnifier.sock')

# File to log errors encountered by this daemon.
ERROR_LOG = '/home/ssh-mitm/log/dockerspawnifier.log'

# Verbose flag (-v).
verbose = False

# Test flag (-t).  Disables TTY output for shells (useful for testing with DockerSpawnifier_TestClient.py).
test_mode = False


# Prints a message if verbose mode is enabled.
def v(s):
    if verbose:
        print(s)


# Thread that handles client connections.
class ClientHandler(threading.Thread):


    def __init__(self, conn):
        threading.Thread.__init__(self, name="ClientHandler")

        # The UNIX socket connection the client will use to tell us whether to run a shell or SFTP Docker container.
        self.c = c

        # The UNIX socket paths on the filesystem that this thread will use to route stdout, stderr, and stdin between the client and Docker container.
        self.docker_stdout_path = None
        self.docker_stderr_path = None
        self.docker_stdin_path = None

        # The UNIX sockets to listen on.
        self.docker_stdout_sock_listener = None
        self.docker_stderr_sock_listener = None
        self.docker_stdin_sock_listener = None

        # The UNIX sockets connected to the client.
        self.docker_stdout_sock_to_client = None
        self.docker_stderr_sock_to_client = None
        self.docker_stdin_sock_to_client = None


    # Closes and deletes stdout, stderr, and stdin sockets.
    def close_and_delete_sockets(self):
        self._close_and_delete_sockets(self.docker_stdout_sock_listener, self.docker_stdout_sock_to_client, self.docker_stdout_path)
        self._close_and_delete_sockets(self.docker_stderr_sock_listener, self.docker_stderr_sock_to_client, self.docker_stderr_path)
        self._close_and_delete_sockets(self.docker_stdin_sock_listener, self.docker_stdin_sock_to_client, self.docker_stdin_path)


    # Closes UNIX sockets, then deletes it from the filesystem.
    def _close_and_delete_sockets(self, sock_listener, sock_client, sock_path):
        if sock_listener is not None:
            sock_listener.shutdown(socket.SHUT_RDWR)
            sock_listener.close()

        if sock_client is not None:
            sock_client.shutdown(socket.SHUT_RDWR)
            sock_client.close()

        try:
            if os.path.exists(sock_path):
                v("Deleting socket: %s" % sock_path)
                os.unlink(sock_path)
        except Exception as e:
            self.log(str(e), str(traceback.format_exc()))
            pass


    # Logs an error to the error log.
    def log(self, exception, stack_trace):
        msg = "Exception: [%s]; Stack trace: [%s]\n" % (exception, stack_trace)

        v(msg)
        with open(ERROR_LOG, 'a') as f:
            f.write(msg)
            f.write("%s\n" % ("=-" * 40))


    # Returns True if the client requests an SFTP session, otherwise False.
    def read_service(self):
        service_name = b''

        newline_not_found = True
        while newline_not_found:
            service_name += self.c.recv(32)
            if service_name.rfind(b"\n") != -1:
                newline_not_found = False

        if service_name == b"sftp\n":
            v("Client requested sftp.")
            return True
        else:
            v("Client requested shell.")
            return False


    # Thread entrypoint.
    def run(self):
        try:
            self._run()
        except Exception as e:
            self.log(str(e), str(traceback.format_exc()))
            self.close_and_delete_sockets()


    def _run(self):
        # True if the client requests SFTP, or False for a shell.
        DOCKER_CMD = DOCKER_CMD_SHELL
        if self.read_service():
            DOCKER_CMD = DOCKER_CMD_SFTP
        elif test_mode:  # Test mode + shell requested.
            DOCKER_CMD[2] = "-i"  # Use -i instead of -it to disable TTY.

        # Bind to unique sockets.  Collision is unlikely but possible, hence this loop.
        found_unique_int = False
        while found_unique_int is False:
            random_int = int.from_bytes(os.urandom(4), byteorder='little')
            self.docker_stdout_path = os.path.join(SOCKET_DIR, "docker_%u_stdout.sock" % random_int)
            self.docker_stderr_path = os.path.join(SOCKET_DIR, "docker_%u_stderr.sock" % random_int)
            self.docker_stdin_path = os.path.join(SOCKET_DIR, "docker_%u_stdin.sock" % random_int)

            self.docker_stdout_sock_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.docker_stderr_sock_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.docker_stdin_sock_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

            # Set the permissions on the sockets to 0700.
            os.fchmod(self.docker_stdout_sock_listener.fileno(), 0o700)
            os.fchmod(self.docker_stderr_sock_listener.fileno(), 0o700)
            os.fchmod(self.docker_stdin_sock_listener.fileno(), 0o700)

            # Attempt to bind to sockets.  If this succeeds, then they are unique.
            try:
                self.docker_stdout_sock_listener.bind(self.docker_stdout_path)
                self.docker_stderr_sock_listener.bind(self.docker_stderr_path)
                self.docker_stdin_sock_listener.bind(self.docker_stdin_path)

                found_unique_int = True
            except OSError as e:
                if e.errno != 98:  # Address already in use (i.e.: collision of existing sockets).
                    raise e

        # Listen for a connection on all sockets.
        self.docker_stdout_sock_listener.listen(1)
        self.docker_stderr_sock_listener.listen(1)
        self.docker_stdin_sock_listener.listen(1)

        # Give the client the random integer, so it can connect to the stdout, stder, and stdin sockets.
        v("Sending random int: %u" % random_int)
        self.c.send(random_int.to_bytes(length=4, byteorder='little'))

        # Accept the connections from the client.
        self.docker_stdout_sock_to_client, _ = self.docker_stdout_sock_listener.accept()
        self.docker_stderr_sock_to_client, _ = self.docker_stderr_sock_listener.accept()
        self.docker_stdin_sock_to_client, _ = self.docker_stdin_sock_listener.accept()

        # Spawn Docker and route its input and output to the client.
        with subprocess.Popen(DOCKER_CMD, env=DOCKER_CLIENT_ENV, bufsize=0, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) as hDocker:

            read_sockets = [hDocker.stdout, hDocker.stderr, self.docker_stdin_sock_to_client]
            pipe_closed = False  # Set when any pipe is closed.
            while pipe_closed is False:

                # Wait for something to read from Docker or from stdin.
                fds, _, _ = select.select(read_sockets, [], [])

                for r in fds:
                    if r == self.docker_stdin_sock_to_client:
                        data = self.docker_stdin_sock_to_client.recv(8192)
                        if len(data) > 0:
                            v("Got stdin from client: [%s]" % data)
                            hDocker.stdin.write(data)
                        else:
                            v("Client stdin closed.")
                            pipe_closed = True

                    elif r == hDocker.stdout:
                        data = hDocker.stdout.read(8192)
                        if len(data) > 0:
                            v("Got stdout from docker: [%s]" % data)
                            self.docker_stdout_sock_to_client.send(data)
                        else:
                            v("Docker stdout closed.")
                            pipe_closed = True

                    elif r == hDocker.stderr:
                        data = hDocker.stderr.read(8192)
                        if len(data) > 0:
                            v("Got stderr from docker: [%s]" % data)
                            self.docker_stderr_sock_to_client.send(data)
                        else:
                            v("Docker stderr closed.")
                            pipe_closed = True

            v("Done reading from sockets.")

        v("Closing and removing sockets...")
        self.close_and_delete_sockets()
        v("Thread done.\n")


# Check if the verbose flag was given.
for i in range(1, len(sys.argv)):
    if sys.argv[i] == '-v':
        verbose = True
        v("Verbose mode enabled.")
    elif sys.argv[i] == '-t':
        verbose = True
        test_mode = True
        v("Test mode and verbose mode enabled.")

# Remove any leftover sockets from a previous invokation.
for filename in os.listdir(SOCKET_DIR):
    if filename.endswith('.sock'):
        socket_path = os.path.join(SOCKET_DIR, filename)
        v("Deleting old socket: %s" % socket_path)
        os.unlink(socket_path)

# Start a server socket to listen on.
master_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
os.fchmod(master_socket.fileno(), 0o700)  # Set socket permission to 0700.
master_socket.bind(MASTER_SOCKET_PATH)
master_socket.listen(32)

# Open the docker daemon log.  Intentionally opened for writing instead of appending so that old output is overwritten.
with open(DOCKER_DAEMON_LOG, 'wb') as log:

    # Run the rootless docker daemon.
    with subprocess.Popen(DOCKER_DAEMON, env=DOCKER_DAEMON_ENV, bufsize=0, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=None) as hDockerDaemon:
        v("Spawned docker daemon as PID %u." % hDockerDaemon.pid)

        while True:
            fds, _, _ = select.select([master_socket, hDockerDaemon.stdout, hDockerDaemon.stderr], [], [])
            for fd in fds:
                if fd == master_socket:
                    # Accept incoming connections and spawn a thread to handle them.
                    c, _ = master_socket.accept()
                    client_handler = ClientHandler(c)
                    client_handler.start()
                else:
                    # Read stdout/stderr from the Docker daemon, and log it.
                    data = fd.read(8192)
                    log.write(data)
                    log.flush()

exit(0)
