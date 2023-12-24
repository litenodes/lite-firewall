from dataclasses import dataclass
import typing

"""
Currently, cache is implemented using built in python dictionaries.
It is assumed that total users amount of one liteserver definitely won't exceed 100 (most likely 10-20).
So, we can store all the data in RAM. If this assumption is wrong, it can be implemented using Redis or Memcached.
"""

users: typing.Dict[bytes: "LsUser"] = {}  # pub_key -> LsUser
whitelist = set()  # pub_key


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


def get_user_by_src(src_ip: str, src_port: int) -> typing.Optional[LsUser]:
    for user in users.values():
        if user.src_ip == src_ip and user.src_port == src_port:
            return user
    return None
