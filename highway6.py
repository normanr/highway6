#!/usr/bin/python

import grp
import os
import pwd
import pytap
import sys
import traceback

from impacket import ImpactDecoder, ImpactPacket, IP6, IP6_Address, ICMP6
import impacket_tuntap

def checkPrefix(prefix, prefix_len):
  mask = '0' * prefix_len + '1' * (128 - prefix_len)
  prefix_bytes = prefix.as_bytes()
  for i in range(len(mask) / 8):
    byte_mask = int(mask[i * 8:i * 8 + 8], 2)
    assert prefix_bytes[i] & byte_mask == 0, 'bits set in prefix mask'

def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        print >>sys.stderr, 'WARNING: Not dropping privileges!'

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(077)

def IP6_Address_Inc(addr, inc):
  for b in xrange(len(addr)-1, -1, -1):
    new = addr[b] + inc
    if new > 0xff:
      addr[b] = new - 0x100
      inc = 1
    else:
      addr[b] = new
      return

if len(sys.argv) < 2:
  print >>sys.stderr, 'Missing prefix'
  sys.exit(1)

try:
  prefix, prefix_len = sys.argv[1].split('/')
  prefix = IP6_Address.IP6_Address(prefix)
  prefix_len = int(prefix_len)
  assert 0 <= prefix_len <= 128, 'Invalid prefix length'
  checkPrefix(prefix, prefix_len)
except Exception as e:
  print >>sys.stderr, 'Invalid prefix: %s' % e
  sys.exit(2)

tap = pytap.TapDevice(name='tun')

os.system('ip route add %s/%d dev %s' % (prefix, prefix_len, tap.name))
os.system('ip link set dev %s up' % tap.name)

drop_privileges()

decoder = impacket_tuntap.TunTapDecoder()
ip6 = IP6.IP6()
ip6.set_hop_limit(64)
tuntap = impacket_tuntap.TunTap()
tuntap.contains(ip6)

while True:
  tuntap_pkt = tap.read()
  try:
    ether_pkt = decoder.decode(tuntap_pkt)
    ip_pkt = ether_pkt.child()
    #print ip_pkt
    if isinstance(ip_pkt, IP6.IP6):
      #print ip_pkt.child()
      icmp6 = ICMP6.ICMP6.Time_Exceeded(
          ICMP6.ICMP6.HOP_LIMIT_EXCEEDED_IN_TRANSIT,
          ip_pkt.get_packet()[:72])
      addr = ip_pkt.get_destination_address().as_bytes()
      IP6_Address_Inc(addr, ip_pkt.get_hop_limit())
      ip6.set_source_address(addr)
      ip6.set_destination_address(ip_pkt.get_source_address().as_bytes())
      ip6.set_traffic_class(ip_pkt.get_traffic_class())
      ip6.set_flow_label(ip_pkt.get_flow_label())
      ip6.contains(icmp6)
      ip6.set_next_header(ip6.child().get_ip_protocol_number())
      ip6.set_payload_length(ip6.child().get_size())
      #print ip6
      #print ip6.child()
      #print ip6.child().child()
      #print ''.join('%02x ' % ord(x) for x in tuntap.get_packet())
      tap.write(tuntap.get_packet())
  except (ImpactPacket.ImpactPacketException) as e:
    print e
