from netfilterqueue import NetfilterQueue
import asyncio
import logging

from .check_peer import check_peer_handshake, check_peer_no_key
from .config import SERVER_KEY_ID


logger = logging.getLogger(__file__)


async def main():
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
    if payload[:32] == SERVER_KEY_ID:
        logger.debug(f'ACCEPT ADNL TCP handshake packet: {payload[32:64].hex()}')
        asyncio.get_event_loop().create_task(check_peer_handshake(pkt, payload[32:64]))
        return
    logger.debug(f'ACCEPT other packet: {pkt_len} bytes')
    asyncio.get_event_loop().create_task(check_peer_no_key(pkt))


nfqueue = NetfilterQueue()
nfqueue.bind(1, process_packet)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
