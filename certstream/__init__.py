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

    # Start watcher tasks
    for task in watcher.get_tasks():
        loop.create_task(task)

    # Run the web server (non-blocking)
    webserver.run_server()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down CertStream...")
    finally:
        loop.close()


if __name__ == "__main__":
    run()
