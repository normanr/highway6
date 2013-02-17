from impacket import ImpactDecoder, ImpactPacket, IP6


class TunTapDecoder(ImpactDecoder.Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        e = TunTap(aBuffer)
        off = e.get_header_size()
        if e.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip_decoder = ImpactDecoder.IPDecoder()
            packet = self.ip_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == IP6.IP6.ethertype:
            self.ip6_decoder = ImpactDecoder.IP6Decoder()
            packet = self.ip6_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ImpactDecoder.ARPDecoder()
            packet = self.arp_decoder.decode(aBuffer[off:])
        else:
            self.data_decoder = ImpactDecoder.DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])

        e.contains(packet)
        return e


class TunTap(ImpactPacket.Header):
    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, 4)
        if(aBuffer):
            self.load_header(aBuffer)

    def set_ether_type(self, aValue):
        "Set ethernet data type field to 'aValue'"
        self.set_word(2, aValue)

    def get_ether_type(self):
        "Return ethernet data type field"
        return self.get_word(2)

    def get_header_size(self):
        "Return size of TunTap header"
        return 4

    def get_packet(self):

        if self.child():
            self.set_ether_type(self.child().ethertype)
        return ImpactPacket.Header.get_packet(self)

    def get_flags(self):
        "Return flags"
        return self.get_word(0)

    def set_ether_dhost(self, aValue):
        "Set flags field to 'aValue'"
        self.set_word(0, aValue)

    def __str__(self):
        tmp_str = 'TunTap: %02x' % self.get_flags()
        if self.child():
            tmp_str += '\n' + self.child().__str__()
        return tmp_str
