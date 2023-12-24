import aiohttp
import asyncio
import logging


class ApiError(Exception):

    def __init__(self, message: str):
        self.message = message


class LocalBackendClient:

    def __init__(self, url: str):
        self._url = url
        self._logger = logging.getLogger(self.__class__.__name__)

    async def _get(self, endpoint: str, params: dict = None) -> dict:
        async with aiohttp.ClientSession() as session:
            async with session.get(self._url + endpoint, params=params) as resp:
                resp = await resp.json()
                if not resp['ok']:
                    self._logger.warning(f'Error in {endpoint}: {resp["message"]}')
                    raise ApiError(resp['message'])
                return await resp.json()

    async def get_pair(self, pub_key: str) -> dict:
        return await self._get('/getPair', {'pub_key': pub_key})

    async def check_payed(self, pub_key: str) -> bool:
        return (await self._get('/checkPayed', {'pub_key': pub_key}))['result']
