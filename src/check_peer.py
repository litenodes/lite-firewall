import time

from .local_back_client import LocalBackendClient, ApiError
from .config import LOCAL_BACK_URL, RPS_LIMIT
from .check_packet import parse_packet
from .cache import users, whitelist, LsUser, get_user_by_src


client = LocalBackendClient(LOCAL_BACK_URL)


async def check_payed_no_throw(pub_key: bytes) -> bool:
    try:
        result = await client.check_payed(pub_key.hex())
    except ApiError as e:
        return False
    return result


async def check_peer_handshake(pkt, pub_key: bytes):
    result = await check_payed_no_throw(pub_key)
    if result:
        await check_peer(pkt, pub_key)
    else:
        pkt.drop()


async def check_peer(pkt, pub_key: bytes):
    parsed = parse_packet(pkt.get_payload())
    user = users.get(pub_key)
    now = int(time.time())
    if not user:
        user = LsUser(
            user_pubkey=pub_key,
            last_checked=now,
            last_sec_req=0,
            last_utime_used=now,
            src_ip=parsed['src'],
            src_port=parsed['sport'],
            is_whitelisted=pub_key in whitelist,
        )
        users[pub_key] = user

    if user.is_whitelisted:
        pkt.accept()
        return

    if now == user.last_utime_used:
        user.last_sec_req += 1
        if user.last_sec_req > RPS_LIMIT:
            pkt.drop()
            return
    else:
        user.last_sec_req = 1
        user.last_utime_used = now
    if user.last_checked < now - 15:
        user.last_checked = now
        result = await check_payed_no_throw(pub_key)
        if not result:
            pkt.drop()
            return
    pkt.accept()


async def check_peer_no_key(pkt):
    parsed = parse_packet(pkt.get_payload())
    user = get_user_by_src(parsed['src'], parsed['sport'])
    if not user:
        pkt.drop()
        return
    await check_peer(pkt, user.user_pubkey)
