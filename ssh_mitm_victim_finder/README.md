# SSH MITM Victim Finder

## Finding Targets

The *JoesAwesomeSSHMITMVictimFinder.py* script makes finding targets on a LAN very easy.  It will ARP spoof a block of IPs and sniff for SSH traffic for a short period of time before moving on to the next block.  Any ongoing SSH connections originating from devices on the LAN are reported.

By default, *JoesAwesomeSSHMITMVictimFinder.py* will ARP spoof and sniff only 5 IPs at a time for 20 seconds before moving onto the next block of 5.  These parameters can be tuned, though a trade-off exists: the more IPs that are spoofed at a time, the greater the chance you will catch an ongoing SSH connection, but also the greater the strain you will put on your puny network interface.  Under too high of a load, your interface will start dropping frames, causing a denial-of-service and greatly raising suspicions (this is bad).  The defaults shouldn't cause problems in most cases, though it'll take longer to find targets.  The block size can be safely raised on low-utilization networks.

Example:

    # ./JoesAwesomeSSHMITMVictimFinder.py --interface enp0s3 --ignore-ips 10.11.12.50,10.11.12.53
    Found local address 10.11.12.141 and adding to ignore list.
    Using network CIDR 10.11.12.141/24.
    Found default gateway: 10.11.12.1
    IP blocks of size 5 will be spoofed for 20 seconds each.
    The following IPs will be skipped: 10.11.12.50 10.11.12.53 10.11.12.141


    Local clients:
      * 10.11.12.70 -> 174.129.77.155:22
      * 10.11.12.43 -> 10.11.99.2:22

The above output shows that two devices on the LAN have created SSH connections (10.11.12.43 and 10.11.12.70); these can be targeted for a man-in-the-middle attack.  Note, however, that in order to potentially intercept credentials, you'll have to wait for them to initiate new connections.  Impatient pentesters may opt to forcefully close existing SSH sessions (using the *tcpkill* tool), prompting clients to create new ones immediately...