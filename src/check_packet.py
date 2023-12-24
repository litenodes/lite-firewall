import logging

from scapy.layers.inet import IP

logger = logging.getLogger(__name__)


def parse_packet(data: bytes):
    import scapy
    c: scapy.layers.inet.IP = IP(data)
    logger.debug(c.show())
    return {'payload': bytes(c.payload.payload), 'src': c.src, 'dst': c.dst, 'sport': c.sport, 'dport': c.dport}
