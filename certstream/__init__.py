import logging

import asyncio

import uvloop

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from certstream.certlib import MerkleTreeHeader
from certstream.watcher import TransparencyWatcher
from certstream.webserver import WebServer

logging.basicConfig(
    format="[%(levelname)s:%(name)s] %(asctime)s - %(message)s", level=logging.INFO
)


def run():
    logging.info("Starting CertStream...")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    watcher = TransparencyWatcher(loop)
    webserver = WebServer(loop, watcher)

    asyncio.gather(*watcher.get_tasks(), *webserver.get_tasks())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down CertStream...")
    finally:
        loop.stop()


if __name__ == "__main__":
    run()
