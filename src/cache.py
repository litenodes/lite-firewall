import time
from dataclasses import dataclass
import typing

"""
Currently, cache is implemented using built in python dictionaries.
It is assumed that total users amount of one liteserver definitely won't exceed 100 (most likely 10-20).
So, we can store all the data in RAM. If this assumption is wrong, it can be implemented using Redis or Memcached.
"""

users: typing.Dict[bytes, "LsUser"] = {}  # pub_key -> LsUser
whitelist = set()  # pub_key
users['last_cleaned'] = 0


def clear_cache():
    now = int(time.time())
    for k, v in list(users.items()):
        if now - v.last_utime_used > 3:
            users.pop(k, None)
    users['last_cleaned'] = now


def get_user(pub_key: bytes):
    clear_cache()
    return users.get(pub_key)


def new_user(pub_key: bytes, now: int, src_ip: str, src_port: int) -> "LsUser":
    user = LsUser(
        user_pubkey=pub_key,
        last_checked=now,
        last_sec_req=0,
        last_utime_used=now,
        src_ip=src_ip,
        src_port=src_port,
        is_whitelisted=pub_key in whitelist,
    )
    users[pub_key] = user
    return user


@dataclass
class LsUser:
    user_pubkey: bytes
    last_utime_used: int
    last_sec_req: int
    # valid_until: int
    last_checked: int  # last checked for is_payed
    src_ip: str
    src_port: int
    is_whitelisted: bool = False


def get_user_by_src(src_ip: str) -> typing.Optional[LsUser]:
    for user in users.values():
        if user.src_ip == src_ip:
            return user
    return None
