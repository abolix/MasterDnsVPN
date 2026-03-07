# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import time


class PingManager:
    def __init__(self, send_func):
        self.send_func = send_func
        self.last_data_activity = time.monotonic()
        self.last_ping_time = self.last_data_activity
        self.active_connections = 0

    def update_activity(self):
        self.last_data_activity = time.monotonic()

    async def ping_loop(self):
        _sleep = asyncio.sleep
        _monotonic = time.monotonic
        _send_func = self.send_func

        while True:
            now = _monotonic()
            idle_time = now - self.last_data_activity

            if self.active_connections == 0 and idle_time > 20.0:
                await _sleep(1.0)
                continue
            elif idle_time >= 10.0:
                ping_interval = 3.0
            elif idle_time >= 5.0:
                ping_interval = 1.0
            else:
                ping_interval = 0.2

            time_since_last_ping = now - self.last_ping_time

            if time_since_last_ping >= ping_interval:
                await _send_func()
                self.last_ping_time = _monotonic()
                await _sleep(ping_interval)
            else:
                await _sleep(0.1)
