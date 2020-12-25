#!/usr/bin/env python3

import asyncio
import zhaquirks
import logging
# import coloredlogs
# coloredlogs.install(milliseconds=True, level=logging.DEBUG)

# There are many different radio libraries but they all have the same API
from zigpy_nrf52.zigbee.application import ControllerApplication

LOGGER = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)-40s %(levelname)-8s %(message)s',
                    datefmt='%H:%M:%s')
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(name)-30s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)

logging.getLogger('').removeHandler(logging.getLogger('').handlers[0])
logging.getLogger('').addHandler(console)

class MainListener:
    """
    Contains callbacks that zigpy will call whenever something happens.
    Look for `listener_event` in the Zigpy source or just look at the logged warnings.
    """

    def __init__(self, application):
        self.application = application

    def device_initialized(self, device, *, new=True):
        """
        Called at runtime after a device's information has been queried.
        I also call it on startup to load existing devices from the DB.
        """
        LOGGER.info("Device is ready: new=%s, device=%s", new, device)

        for ep_id, endpoint in device.endpoints.items():
            # Ignore ZDO
            if ep_id == 0:
                continue

            # You need to attach a listener to every cluster to receive events
            for cluster in endpoint.in_clusters.values():
                # The context listener passes its own object as the first argument
                # to the callback
                cluster.add_context_listener(self)

    def attribute_updated(self, cluster, attribute_id, value):
        # Each object is linked to its parent (i.e. app > device > endpoint > cluster)
        device = cluster.endpoint.device

        LOGGER.info("Received an attribute update %s=%s on cluster %s from device %s",
            attribute_id, value, cluster, device)


async def main():
    app = await ControllerApplication.new(
        config=ControllerApplication.SCHEMA({
            "database_path": "zigbee.db",
            "device": {
                # "path": "/dev/ttyACM0",
                "path": "/dev/serial/by-id/usb-Nordic_Semiconductor_nRF52_Zigbee_Dongle_D43CE6C091E3-if00"
            },
            # "network": {
            #     "channels": [1<<13, 1<<16, 1<<19]
            # }
        }),
        auto_form=True,
    )

    listener = MainListener(app)
    app.add_listener(listener)

    # Have every device in the database fire the same event so you can attach listeners
    for device in app.devices.values():
        listener.device_initialized(device, new=False)

    # Permit joins for a minute
    await app.permit(60)
    # await asyncio.sleep(3)

    # Run forever
    LOGGER.info("run forever")
    await asyncio.get_running_loop().create_future()



if __name__ == "__main__":
    asyncio.run(main())
