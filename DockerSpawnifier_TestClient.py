#!/usr/bin/env python3
"""
DockerSpawnifier_TestClient.py
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


This program tests the DockerSpawnifier.py daemon.
"""

import os
import select
import socket
import sys
import time


SOCKET_DIR = '/home/ssh-mitm/tmp/'
MASTER_SOCKET_PATH = os.path.join(SOCKET_DIR, 'dockerspawnifier.sock')
RECONNECT_TRIES_PER_SECOND = 5
RECONNECT_WAIT = 15  # Continue trying to re-connect for up to this many seconds.

# Repeatedly tries to connect to a socket up to RECONNECT_WAIT seconds.
def connect_with_timeout(s, path):
    connected = False
    failed = 0

    while (connected is False) and (failed < (RECONNECT_TRIES_PER_SECOND * RECONNECT_WAIT)):
        try:
            s.connect(path)
            connected = True
        except ConnectionRefusedError:
            print("Failed to connect to %s. [%u / %u]" % (path, failed + 1, RECONNECT_TRIES_PER_SECOND * RECONNECT_WAIT))
            time.sleep(1 / RECONNECT_TRIES_PER_SECOND)
            failed += 1

    print("Connected to %s." % path)
    return connected


sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(MASTER_SOCKET_PATH)


service = -1

while service not in [0, 1]:
    print("Which service would you like to spawn? [0=Shell, 1=SFTP] ", end="", flush=True)
    try:
        service = int(input())
    except ValueError as e:
        pass

service_str = "shell"
if service == 1:
    service_str = "sftp"

print("Requesting %s service..." % service_str)
sock.sendall(("%s\n" % service_str).encode('ascii'))

random_int = int.from_bytes(sock.recv(4), byteorder='little')
sock.close()

print("Got random int: %u" % random_int)

docker_stdout_path = os.path.join(SOCKET_DIR, "docker_%u_stdout.sock" % random_int)
docker_stderr_path = os.path.join(SOCKET_DIR, "docker_%u_stderr.sock" % random_int)
docker_stdin_path = os.path.join(SOCKET_DIR, "docker_%u_stdin.sock" % random_int)

docker_stdout_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
docker_stderr_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
docker_stdin_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

if not connect_with_timeout(docker_stdout_sock, docker_stdout_path):
    print("Failed to connect to stdout socket.")
    exit(-1)

if not connect_with_timeout(docker_stderr_sock, docker_stderr_path):
    print("Failed to connect to stderr socket.")
    exit(-1)
    
if not connect_with_timeout(docker_stdin_sock, docker_stdin_path):
    print("Failed to connect to stdin socket.")
    exit(-1)

print("\n\nConnected to Docker container.  Note that an input handling bug in this program results in commands needing to be terminated with TWO enter keys instead of one.\n")
socket_closed = False
read_sockets = [docker_stdout_sock, docker_stderr_sock, sys.stdin]
while socket_closed is False:
    fds, _, _ = select.select(read_sockets, [], [])

    # The user typed in input at the console.  Send it to the stdin socket.
    if sys.stdin in fds:
        data = sys.stdin.read(1)
        docker_stdin_sock.sendall(data.encode('ascii'))
        continue

    # Output is available in the stdout and/or stderr sockets.  Read and print it to the console.
    for fd in fds:
        title = "stdout: ["
        if fd == docker_stderr_sock:
            title = "stderr: ["

        data = fd.recv(1024)
        if len(data) > 0:
            print("%s%s]" % (title, data))
        else:
            print("Detected socket EOF.  Terminating...")
            socket_closed = True

print("Closing sockets...")
docker_stdout_sock.close()
docker_stderr_sock.close()
docker_stdin_sock.close()

print("Done.")
exit(0)
