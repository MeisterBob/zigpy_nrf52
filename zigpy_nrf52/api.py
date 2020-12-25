# import re
# import string
from typing import Any, Dict, Optional

import asyncio
import serial_asyncio
from functools import partial

import logging
LOGGER = logging.getLogger(__name__)

# import zigpy.types
# from zigpy.zdo.types import ZDOCmd

import zigpy_nrf52.protocol

class nRF52:
    def __init__(self, device_config: Dict[str, Any]) -> None:
        self._config                  = device_config
        self._app                     = None
        self._conn                    = None
        self._tx_queue: asyncio.Queue = None
        self._rx_queue: asyncio.Queue = None

    @classmethod
    async def new(cls, application: "zigpy_nrf52.zigbee.application.ControllerApplication", config: Dict[str, Any]) -> "XBee":
        """Create new instance from """
        nrf52_api              = cls(config)
        nrf52_api._application = application
        nrf52_api._config      = config
        loop                   = asyncio.get_event_loop()
        nrf52_api._tx_queue    = asyncio.Queue()
        nrf52_api._rx_queue    = asyncio.Queue()
        proto_partial          = partial (zigpy_nrf52.protocol.SerialProtocol, nrf52_api._tx_queue, nrf52_api._rx_queue)
        nrf52_api._conn        = serial_asyncio.create_serial_connection(loop, proto_partial, nrf52_api._config["device"]["path"], baudrate=115200)
        asyncio.ensure_future(nrf52_api._conn)
        asyncio.ensure_future(nrf52_api.rx_queue_watcher())
        return nrf52_api

    @classmethod
    async def close(self):
        await self.write("reset")

    async def write(self, msg):
        await self._tx_queue.put(msg)

    async def rx_queue_watcher(self):
        while True:
            data = await self._rx_queue.get()
            # LOGGER.info(data)
            self._application.handle_rx(data["ieee"], data["nwk"], data["src_ep"], data["dst_ep"], data["cluster"], data["profile"], data["data"])