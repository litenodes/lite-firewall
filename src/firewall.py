from netfilterqueue import NetfilterQueue
import asyncio
import logging

from .check_packet import parse_packet
from .check_peer import check_peer_handshake, check_peer_no_key
from .config import SERVER_KEY_ID, DEBUG_LOGGING


logger = logging.getLogger(__file__)


def main():
    loop = asyncio.get_event_loop()

    def on_readable():
        nfqueue.run(block=False)

    loop.add_reader(nfqueue.get_fd(), on_readable)
    loop.run_forever()


def process_packet(pkt):
    payload = pkt.get_payload()
    pkt_len = len(payload)
    if pkt_len < 32:  # too small packet
        logger.debug('DROP: too small packet')
        pkt.drop()
        return
    if pkt_len < 68:  # probably tcp handshake packet
        logger.debug('ACCEPT: tcp handshake packet')
        pkt.accept()  # todo: check if packet is tcp handshake
        return
    parsed = parse_packet(payload)
    if parsed['src'] == '127.0.0.1':
        logger.debug(f'ACCEPT: local packet')
        pkt.accept()
        return
    data = parsed['payload']
    logger.debug(f'packet {len(data)} bytes from {parsed["src"]}:{parsed["sport"]}')
    if data[:32] == SERVER_KEY_ID:
        logger.debug(f'ACCEPT ADNL TCP handshake packet: {data[32:64].hex()}')
        asyncio.get_event_loop().create_task(check_peer_handshake(pkt, data[32:64], parsed))
        return
    logger.debug(f'ACCEPT other packet: {pkt_len} bytes')
    asyncio.get_event_loop().create_task(check_peer_no_key(pkt, parsed))


if DEBUG_LOGGING:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

nfqueue = NetfilterQueue()
nfqueue.bind(1, process_packet)
try:
    main()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
