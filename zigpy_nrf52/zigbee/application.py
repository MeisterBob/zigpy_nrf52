import asyncio
import binascii
import logging
import time
from typing import Any, Dict, Optional
import serial

import zigpy.application
import zigpy.config
import zigpy.device
import zigpy.exceptions
import zigpy.quirks
import zigpy.types
import zigpy.util
from zigpy.zcl.clusters.general import Groups
from zigpy.zdo.types import NodeDescriptor, ZDOCmd

from zigpy_nrf52.config import CONF_DEVICE, CONF_DEVICE_PATH, CONFIG_SCHEMA, SCHEMA_DEVICE
import zigpy_nrf52.types as t
import zigpy_nrf52.api

NRF52_ENDPOINT_ID = 1

LOGGER = logging.getLogger(__name__)

class ControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, config: Dict[str, Any]):
        LOGGER.info("__init__")
        # LOGGER.info(config)
        super().__init__(config=zigpy.config.ZIGPY_SCHEMA(config))
        self._config  = config
        self._api: Optional[zigpy_nrf52.api.nRF52] = None

    # @abc.abstractmethod
    async def shutdown(self):
        """Shutdown application."""
        await self._api.write("reset")
        LOGGER.info("shutdown")

    # @abc.abstractmethod
    async def startup(self, auto_form=False):
        """Perform a complete application startup"""
        LOGGER.info("startup")

        self._api = await zigpy_nrf52.api.nRF52.new(self, self._config)
        LOGGER.info("connected")
        await self._api.write("log enable info app")
        await self._api.write("log enable info zboss")
        await self._api.write("log enable info zigbee.*")

        if auto_form:
            await self.form_network()

    # NotImplementedError
    async def form_network(self, channel=16, pan_id=None, extended_pan_id=None):
        LOGGER.info("Forming network on channel %s", channel)
        # self._cli_dev.bdb.nwkkey   = config_dict['network'][ToDo]
        LOGGER.info("setting channel")
        await self._api.write("bdb channel {}".format(channel))
        LOGGER.info("setting role")
        await self._api.write("bdb role zc")
        if pan_id is not None:
            LOGGER.info("setting panid")
            await self._api.write("bdb panid {}".format(pan_id))
        if extended_pan_id is not None:
            LOGGER.info("setting extended panid")
            await self._api.write("bdb extpanid {}".format(extended_pan_id))

        await self._api.write("bdb start")

    # NotImplementedError
    # async def update_network(self, *, channel: Optional[t.uint8_t] = None, channels: Optional[t.Channels] = None, extended_pan_id: Optional[t.ExtendedPanId] = None, network_key: Optional[t.KeyData] = None, pan_id: Optional[t.PanId] = None, tc_link_key: Optional[t.KeyData] = None, update_id: int = 0):
    #     """Update network parameters.

    #     :param channel: Radio channel
    #     :param channels: Channels mask
    #     :param extended_pan_id: Extended pan id
    #     :param network_key: network key
    #     :param pan_id: Network pan id
    #     :param tc_link_key: Trust Center link key
    #     :param update_id: nwk_update_id parameter
    #     """
    #     LOGGER.info("update_network")

    # NotImplementedError
    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""
        LOGGER.info("force_remove")
        pass

    # NotImplementedError
    async def mrequest(self, group_id, profile, cluster, src_ep, sequence, data, *, hops=0, non_member_radius=3):
        """Submit and send data out as a multicast transmission.
        :param group_id: destination multicast address
        :param profile: Zigbee Profile ID to use for outgoing message
        :param cluster: cluster id where the message is being sent
        :param src_ep: source endpoint id
        :param sequence: transaction sequence number of the message
        :param data: Zigbee message payload
        :param hops: the message will be delivered to all nodes within this number of
                     hops of the sender. A value of zero is converted to MAX_HOPS
        :param non_member_radius: the number of hops that the message will be forwarded
                                  by devices that are not members of the group. A value
                                  of 7 or greater is treated as infinite
        :returns: return a tuple of a status and an error_message. Original requestor
                  has more context to provide a more meaningful error message
        """
        LOGGER.debug("mrequest #%s: %s", sequence, binascii.hexlify(data))

    # @abc.abstractmethod
    async def request(self, device, profile, cluster, src_ep, dst_ep, sequence, data, expect_reply=True, use_ieee=False):
        """Submit and send data out as an unicast transmission.

        :param device: destination device
        :param profile: Zigbee Profile ID to use for outgoing message
        :param cluster: cluster id where the message is being sent
        :param src_ep: source endpoint id
        :param dst_ep: destination endpoint id
        :param sequence: transaction sequence number of the message
        :param data: Zigbee message payload
        :param expect_reply: True if this is essentially a request
        :param use_ieee: use EUI64 for destination addressing
        :returns: return a tuple of a status and an error_message. Original requestor
                  has more context to provide a more meaningful error message
        """
        LOGGER.debug(f'request #{sequence}: D:{device} P:{profile} C:{cluster} {src_ep}->{dst_ep} R:{expect_reply} I:{use_ieee} {binascii.hexlify(data)}')
        # await self._api.write(f'zcl cmd {device.ieee if use_ieee else device.nwk} {dst_ep} {cluster}{" -p" if profile>0 else ""}{profile if profile>0 else ""} {binascii.hexlify(data).decode()}')

    # NotImplementedError
    async def broadcast(self, profile, cluster, src_ep, dst_ep, grpid, radius, sequence, data, broadcast_address=zigpy.types.BroadcastAddress.RX_ON_WHEN_IDLE):
        """Submit and send data out as an broadcast transmission.

        :param profile: Zigbee Profile ID to use for outgoing message
        :param cluster: cluster id where the message is being sent
        :param src_ep: source endpoint id
        :param dst_ep: destination endpoint id
        :param grpid: group id to address the broadcast to
        :param radius: max radius of the broadcast
        :param sequence: transaction sequence number of the message
        :param data: zigbee message payload
        :param broadcast_address: broadcast address.
        :returns: return a tuple of a status and an error_message. Original requestor
                  has more context to provide a more meaningful error message
        """
        LOGGER.debug("Broadcast request seq %s", sequence)

    # @abc.abstractmethod
    async def permit_ncp(self, time_s=60):
        LOGGER.debug("permit_ncp %d", time_s)

    # @abc.abstractmethod
    async def probe(config) -> bool:
        """Probe port for the device presence."""
        LOGGER.info("probe")
        LOGGER.info(config)
        try:
            LOGGER.info("trying to get device description")
            device = next(serial.tools.list_ports.grep(config["path"]))
            if device.description == 'nRF52 Zigbee Dongle':
                return True
        except StopIteration:
            LOGGER.error("couldn't get device description")
            return False

        return False

    def handle_rx(self, src_ieee, src_nwk, src_ep, dst_ep, cluster_id, profile_id, data):
        if src_nwk == 0:
            LOGGER.info("handle_rx self addressed")

        LOGGER.info("zigpy_nrf52.zigbee.application.handle_rx")
        ember_ieee = zigpy.types.EUI64(src_ieee)
        if dst_ep == 0 and cluster_id == ZDOCmd.Device_annce:
            # ZDO Device announce request
            nwk, rest = zigpy.types.NWK.deserialize(data[1:])
            ieee, rest = zigpy.types.EUI64.deserialize(rest)
            LOGGER.info("New device joined: NWK 0x%04x, IEEE %s + %s", nwk, ieee, rest)
            if ember_ieee != ieee:
                LOGGER.warning(
                    "Announced IEEE %s is different from originator %s",
                    str(ieee),
                    str(ember_ieee),
                )
            if src_nwk != nwk:
                LOGGER.warning(
                    "Announced 0x%04x NWK is different from originator 0x%04x",
                    nwk,
                    src_nwk,
                )
            self.handle_join(nwk, ieee, 0)

        try:
            self.devices[self.ieee].last_seen = time.time()
        except KeyError:
            pass
        try:
            device = self.get_device(nwk=src_nwk)
        except KeyError:
            if ember_ieee != t.UNKNOWN_IEEE and ember_ieee in self.devices:
                self.handle_join(src_nwk, ember_ieee, 0)
                device = self.get_device(ieee=ember_ieee)
            else:
                LOGGER.debug(
                    "Received frame from unknown device: 0x%04x/%s",
                    src_nwk,
                    str(ember_ieee),
                )
                return

        self.handle_message(device, profile_id, cluster_id, src_ep, dst_ep, data)
