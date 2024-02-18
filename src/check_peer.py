import time
import logging

from .local_back_client import LocalBackendClient, ApiError
from .config import LITE_BACK_PORT, RPS_LIMIT
from .cache import whitelist, get_user_by_src, new_user, get_user


client = LocalBackendClient(f'http://127.0.0.1:{LITE_BACK_PORT}/')
logger = logging.getLogger(__file__)


async def check_payed_no_throw(pub_key: bytes) -> bool:
    try:
        result = await client.check_payed(pub_key.hex())
    except ApiError as e:
        return False
    return result


async def check_peer_handshake(pkt, pub_key: bytes, parsed):
    if pub_key in whitelist:
        await check_peer(pkt, pub_key, parsed)
        return
    result = await check_payed_no_throw(pub_key)
    if result:
        logger.info(f'ACCEPT: handshake payed: {pub_key.hex()}')
        await check_peer(pkt, pub_key, parsed)
    else:
        logger.debug(f'DROP: not payed: {pub_key.hex()}')
        pkt.drop()


async def check_peer(pkt, pub_key: bytes, parsed):
    user = get_user(pub_key)
    now = int(time.time())

    if not user:
        new_user(pub_key, now, parsed['src'], parsed['sport'])

    if user.is_whitelisted:
        logger.info(f'ACCEPT: whitelisted: {pub_key.hex()}')
        pkt.accept()
        return

    if now == user.last_utime_used:
        user.last_sec_req += 1
        if user.last_sec_req > RPS_LIMIT:
            logger.info(f'DROP: exceeded RPS limit: {pub_key.hex()}')
            pkt.drop()
            return
    else:
        user.last_sec_req = 1
        user.last_utime_used = now
    if user.last_checked < now - 15:
        user.last_checked = now
        result = await check_payed_no_throw(pub_key)
        if not result:
            logger.info(f'DROP: not payed: {pub_key.hex()}')
            pkt.drop()
            return
    logger.info(f'ACCEPT: payed: {pub_key.hex()}')
    pkt.accept()


async def check_peer_no_key(pkt, parsed):
    user = get_user_by_src(parsed['src'])
    if not user:
        logger.debug(f'DROP: no user found: {parsed["src"]}:{parsed["sport"]}')
        pkt.drop()
        return
    await check_peer(pkt, user.user_pubkey, parsed)
