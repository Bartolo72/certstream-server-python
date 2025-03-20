import aiohttp
import asyncio
import logging
import math
import requests
import sys
import os

from asyncio import AbstractEventLoop, Queue, Task
from logging import Logger
from typing import Any, AsyncGenerator

from certstream.certlib import parse_ctl_entry


class TransparencyWatcher(object):
    # These are a list of servers that we shouldn't even try to connect to. In testing they either had bad
    # DNS records, resolved to un-routable IP addresses, or didn't have valid SSL certificates.
    BAD_CT_SERVERS: list[str] = [
        "alpha.ctlogs.org",
        "clicky.ct.letsencrypt.org",
        "ct.akamai.com",
        "ct.filippo.io/behindthesofa",
        "ct.gdca.com.cn",
        "ct.izenpe.com",
        "ct.izenpe.eus",
        "ct.sheca.com",
        "ct.startssl.com",
        "ct.wosign.com",
        "ctlog.api.venafi.com",
        "ctlog.gdca.com.cn",
        "ctlog.sheca.com",
        "ctlog.wosign.com",
        "ctlog2.wosign.com",
        "flimsy.ct.nordu.net:8080",
        "log.certly.io",
        "nessie2021.ct.digicert.com/log",
        "plausible.ct.nordu.net",
        "www.certificatetransparency.cn/ct",
    ]

    MAX_BLOCK_SIZE: int = 64

    def __init__(self: "TransparencyWatcher", _loop: AbstractEventLoop) -> None:
        self.loop: AbstractEventLoop = _loop
        self.stopped: bool = False
        self.logger: Logger = logging.getLogger("certstream.watcher")
        self.stream: Queue = Queue(maxsize=3000)
        self.logger.info("Initializing the CTL watcher")

    def _initialize_ts_logs(self: "TransparencyWatcher") -> None:
        try:
            self.transparency_logs: dict[str, Any] = requests.get(
                "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
            ).json()
            # https://www.gstatic.com/ct/log_list/all_logs_list.json is not available anymore
            # https://www.gstatic.com/ct/log_list/v3/all_logs_list.json use this instead

        except Exception as e:
            self.logger.fatal(
                f"Invalid response from certificate directory! Exiting :(\nError: {str(e)}"
            )
            sys.exit(1)

        for operator in self.transparency_logs["operators"]:
            self.logger.info(
                f"Retrieved transparency log with {len(operator['logs'])} entries to watch."
            )
            for entry in operator["logs"]:
                if entry["url"].endswith("/"):
                    entry["url"] = entry["url"][:-1]
                self.logger.info(f"  + {entry['description']}")

    async def _print_memory_usage(self: "TransparencyWatcher") -> None:
        import objgraph
        import gc

        while True:
            print(f"Stream backlog : {self.stream.qsize()}")
            gc.collect()
            objgraph.show_growth()
            await asyncio.sleep(60)

    def get_tasks(self: "TransparencyWatcher") -> list[Task]:
        self._initialize_ts_logs()

        coroutines: list[Task] = []

        if os.getenv("DEBUG_MEMORY", False):
            coroutines.append(self._print_memory_usage())

        for operator in self.transparency_logs["operators"]:
            for log in operator["logs"]:
                if log["url"] not in self.BAD_CT_SERVERS:
                    coroutines.append(self.watch_for_updates_task(log))

        return coroutines

    def stop(self: "TransparencyWatcher") -> None:
        self.logger.info("Got stop order, exiting...")
        self.stopped = True

    async def watch_for_updates_task(
        self: "TransparencyWatcher", operator_information: dict[str, Any]
    ) -> None:
        try:
            latest_size: int = 0
            name: str = operator_information["description"]
            while not self.stopped:
                url: str = f"{operator_information['url']}/ct/v1/get-sth"
                try:
                    async with aiohttp.ClientSession(loop=self.loop) as session:
                        async with session.get(url) as response:
                            info: dict[str, Any] = await response.json()
                except aiohttp.ClientError as e:
                    self.logger.info(
                        f"[{name}] Exception when connecting to: {url} -> {e}"
                    )
                    await asyncio.sleep(600)
                    continue

                tree_size: int = info.get("tree_size")

                # TODO: Add in persistence and id tracking per log
                if latest_size == 0:
                    latest_size = tree_size

                if latest_size < tree_size:
                    self.logger.info(
                        f"[{name}] [{latest_size} -> {tree_size}] New certs found, updating!"
                    )

                    try:
                        async for result_chunk in self.get_new_results(
                            operator_information, latest_size, tree_size
                        ):
                            for entry in result_chunk:
                                cert_data: dict[str, Any] = parse_ctl_entry(
                                    entry, operator_information
                                )
                                await self.stream.put(cert_data)

                    except aiohttp.ClientError as e:
                        self.logger.info(f"[{name}] Exception -> {e}")
                        await asyncio.sleep(600)
                        continue

                    except Exception as e:
                        print(
                            f"Encountered an exception while getting new results! -> {e}"
                        )
                        return

                    latest_size = tree_size
                else:
                    self.logger.debug(
                        f"[{name}][{latest_size}|{tree_size}] No update needed, continuing..."
                    )

                await asyncio.sleep(30)
        except Exception as e:
            print(f"Encountered an exception while getting new results! -> {e}")
            return

    async def get_new_results(
        self: "TransparencyWatcher",
        operator_information: dict[str, Any],
        latest_size: int,
        tree_size: int,
    ) -> AsyncGenerator[list[dict[str, Any]], None]:
        # The top of the tree isn't actually a cert yet, so the total_size is what we're aiming for
        total_size: int = tree_size - latest_size
        start: int = latest_size
        end: int = start + self.MAX_BLOCK_SIZE
        chunks: int = math.ceil(total_size / self.MAX_BLOCK_SIZE)

        self.logger.info(
            f"Retrieving {tree_size - latest_size} certificates ({latest_size} -> {tree_size}) for {operator_information['description']}"
        )
        async with aiohttp.ClientSession(loop=self.loop) as session:
            for _ in range(chunks):
                # Cap the end to the last record in the DB
                if end >= tree_size:
                    end = tree_size - 1

                assert end >= start, f"End {end} is less than start {start}!"
                assert end < tree_size, f"End {end} is less than tree_size {tree_size}"

                url: str = (
                    f"{operator_information['url']}/ct/v1/get-entries?start={start}&end={end}"
                )
                async with session.get(url) as response:
                    certificates: dict[str, Any] = await response.json()
                    if "error_message" in certificates:
                        print("error!")

                    for index, cert in zip(
                        range(start, end + 1), certificates["entries"]
                    ):
                        cert["index"] = index

                    yield certificates["entries"]

                start += self.MAX_BLOCK_SIZE

                end = start + self.MAX_BLOCK_SIZE + 1


class DummyTransparencyWatcher(object):
    stream = asyncio.Queue()

    def get_tasks(self: "DummyTransparencyWatcher") -> list[Task]:
        return []


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    watcher = TransparencyWatcher(loop)
    loop.run_until_complete(asyncio.gather(*watcher.get_tasks()))
