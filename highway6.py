#!/usr/bin/python3

import grp
import os
import pwd
from pytap2.src import pytap2
import sys
import traceback

from impacket import ImpactDecoder, ImpactPacket, IP6, IP6_Address, ICMP6

def checkPrefix(prefix, prefix_len):
  mask = '0' * prefix_len + '1' * (128 - prefix_len)
  prefix_bytes = prefix.as_bytes()
  for i in range(int(len(mask) / 8)):
    byte_mask = int(mask[i * 8:i * 8 + 8], 2)
    assert prefix_bytes[i] & byte_mask == 0, 'bits set in prefix mask'

def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        print('WARNING: Not dropping privileges!', file=sys.stderr)

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(0o77)

def IP6_Address_Inc(addr, inc):
  for b in range(len(addr)-1, -1, -1):
    new = addr[b] + inc
    if new > 0xff:
      addr[b] = new - 0x100
      inc = 1
    else:
      addr[b] = new
      return

if len(sys.argv) < 2:
  print('Missing prefix', file=sys.stderr)
  sys.exit(1)

try:
  prefix, prefix_len = sys.argv[1].split('/')
  prefix = IP6_Address.IP6_Address(prefix)
  prefix_len = int(prefix_len)
  assert 0 <= prefix_len <= 128, 'Invalid prefix length'
  checkPrefix(prefix, prefix_len)
except Exception as e:
  print('Invalid prefix: %s' % e, file=sys.stderr)
  sys.exit(2)

tap = pytap2.TapDevice(name='tun')

os.system('ip link set dev %s up' % tap.name)
os.system('ip route add %s/%d dev %s' % (prefix, prefix_len, tap.name))

drop_privileges()

ip6_decoder = ImpactDecoder.IP6Decoder()
ip6 = IP6.IP6()
ip6.set_hop_limit(64)

while True:
  tuntap_pkt = tap.read()
  try:
    if not tuntap_pkt:
      continue
    ip_v = (tuntap_pkt[0] & 0xF0) >> 4
    if ip_v == 6:
      ip_pkt = ip6_decoder.decode(tuntap_pkt)
    else:
      ip_pkt = None
    #print(ip_pkt)
    if isinstance(ip_pkt, IP6.IP6):
      #print(ip_pkt.child())
      icmp6 = ICMP6.ICMP6.Time_Exceeded(
          ICMP6.ICMP6.HOP_LIMIT_EXCEEDED_IN_TRANSIT,
          ip_pkt.get_packet()[:72])
      addr = ip_pkt.get_ip_dst().as_bytes()
      IP6_Address_Inc(addr, ip_pkt.get_hop_limit())
      ip6.set_ip_src(addr)
      ip6.set_ip_dst(ip_pkt.get_ip_src().as_bytes())
      ip6.set_traffic_class(ip_pkt.get_traffic_class())
      ip6.set_flow_label(ip_pkt.get_flow_label())
      ip6.contains(icmp6)
      ip6.set_next_header(ip6.child().get_ip_protocol_number())
      ip6.set_payload_length(ip6.child().get_size())
      #print(ip6)
      #print(ip6.child())
      #print(ip6.child().child())
      #print(''.join('%02x ' % x for x in ip6.get_packet()))
      tap.write(ip6.get_packet())
  except (ImpactPacket.ImpactPacketException) as e:
    print(e)
