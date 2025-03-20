import asyncio
import collections
import json
import logging
import os
import time
import ssl
from aiohttp import web
from aiohttp.web_urldispatcher import Response
from aiohttp.web_ws import WebSocketResponse, WebSocketReady

from asyncio import AbstractEventLoop, Task, Queue
from logging import Logger
from typing import Any

from certstream.util import pretty_date, get_ip
from certstream.watcher import TransparencyWatcher

WebsocketClientInfo: tuple = collections.namedtuple(
    "WebsocketClientInfo", ["external_ip", "queue", "connection_time"]
)

STATIC_INDEX: str = f"""
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Open+Sans:400,700" rel="stylesheet">
  </head>
  <body>
    <div id="app"></div>
  <script type="text/javascript" src="https://storage.googleapis.com/certstream-prod/build.js?v={time.time()}"></script></body>
</html>
"""


class WebServer(object):
    def __init__(
        self: "WebServer",
        _loop: AbstractEventLoop,
        transparency_watcher: TransparencyWatcher,
    ) -> None:
        self.active_sockets: list[tuple] = []
        self.recently_seen: collections.deque = collections.deque(maxlen=25)
        self.stats_url: str = os.getenv("STATS_URL", "stats")
        self.logger: Logger = logging.getLogger("certstream.webserver")
        self.loop: AbstractEventLoop = _loop
        self.watcher: TransparencyWatcher = transparency_watcher

        self.app: web.Application = web.Application()
        self._add_routes()

    async def run_server(self: "WebServer") -> None:
        if os.environ.get("NOSSL", False):
            ssl_ctx = None
        else:
            ssl_ctx: ssl.SSLContext = ssl.create_default_context(
                ssl.Purpose.CLIENT_AUTH
            )
            ssl_ctx.load_cert_chain(
                certfile=os.getenv("SERVER_CERT", "server.crt"),
                keyfile=os.getenv("SERVER_KEY", "server.key"),
            )

        await web._run_app(
            self.app, port=int(os.environ.get("PORT", 8080)), ssl_context=None
        )

    def get_tasks(self: "WebServer") -> list[Task]:
        return [self.mux_ctl_stream(), self.ws_heartbeats(), self.run_server()]

    def stop(self: "WebServer") -> None:
        self.logger.info("Shutting down webserver...")
        for task in asyncio.all_tasks():
            task.cancel()

    def _add_routes(self: "WebServer") -> None:
        self.app.router.add_get("/latest.json", self.latest_json_handler)
        self.app.router.add_get("/example.json", self.example_json_handler)
        self.app.router.add_get(f"/{self.stats_url}", self.stats_handler)
        self.app.router.add_get("/", self.root_handler)
        self.app.router.add_get("/develop", self.dev_handler)

    async def mux_ctl_stream(self: "WebServer") -> None:
        while True:
            cert_data: dict[str, Any] = await self.watcher.stream.get()
            data_packet: dict[str, Any] = {
                "message_type": "certificate_update",
                "data": cert_data,
            }

            self.recently_seen.append(data_packet)

            for client in self.active_sockets:
                try:
                    client.queue.put_nowait(data_packet)
                except asyncio.QueueFull:
                    pass

    async def dev_handler(
        self: "WebServer", request: Response
    ) -> WebSocketResponse | web.Response:
        # If we have a websocket request
        if request.headers.get("Upgrade"):
            ws: WebSocketResponse = WebSocketResponse()

            await ws.prepare(request)

            try:
                for message in self.recently_seen:
                    message_json: str = json.dumps(message)
                    await ws.send_str(message_json)
            except asyncio.CancelledError:
                print("websocket cancelled")

            await ws.close()
            return ws

        return web.Response(
            body=json.dumps(
                {"error": "Please use this url with a websocket client!"}, indent=4
            ),
            content_type="application/json",
        )

    async def root_handler(
        self: "WebServer", request: Response
    ) -> WebSocketResponse | web.Response:
        resp: WebSocketResponse = WebSocketResponse()
        available: WebSocketReady = resp.can_prepare(request)
        if not available:
            return Response(body=STATIC_INDEX, content_type="text/html")

        await resp.prepare(request)

        client_queue: Queue = Queue(maxsize=500)

        client: tuple = WebsocketClientInfo(
            external_ip=get_ip(request),
            queue=client_queue,
            connection_time=int(time.time()),
        )

        try:
            self.logger.info(f"Client {client.external_ip} joined.")
            self.active_sockets.append(client)
            while True:
                message: dict[str, Any] = await client_queue.get()
                message_json: str = json.dumps(message)
                await resp.send_str(message_json)

        finally:
            self.active_sockets.remove(client)
            self.logger.info(f"Client {client.external_ip} disconnected.")

    async def latest_json_handler(self: "WebServer", _: Any) -> web.Response:
        return web.Response(
            body=json.dumps({"messages": list(self.recently_seen)}, indent=4),
            headers={"Access-Control-Allow-Origin": "*"},
            content_type="application/json",
        )

    async def example_json_handler(self: "WebServer", _: Any) -> web.Response:
        if self.recently_seen:
            return web.Response(
                body=json.dumps(list(self.recently_seen)[0], indent=4),
                headers={"Access-Control-Allow-Origin": "*"},
                content_type="application/json",
            )
        else:
            return web.Response(
                body="{}",
                headers={"Access-Control-Allow-Origin": "*"},
                content_type="application/json",
            )

    async def stats_handler(self: "WebServer", _: Any) -> web.Response:
        clients: dict[str, Any] = {}
        for client in self.active_sockets:
            client_identifier: str = f"{client.external_ip}-{client.connection_time}"
            clients[client_identifier] = {
                "ip_address": client.external_ip,
                "conection_time": client.connection_time,
                "connection_length": pretty_date(client.connection_time),
                "queue_size": client.queue.qsize(),
            }

        return web.Response(
            body=json.dumps(
                {
                    "connected_client_count": len(self.active_sockets),
                    "clients": clients,
                },
                indent=4,
            ),
            content_type="application/json",
        )

    async def ws_heartbeats(self: "WebServer") -> None:
        self.logger.info("Starting WS heartbeat coro...")
        while True:
            await asyncio.sleep(30)
            self.logger.debug("Sending ping...")
            timestamp: float = time.time()
            for client in self.active_sockets:
                await client.queue.put(
                    {"message_type": "heartbeat", "timestamp": timestamp}
                )


if __name__ == "__main__":
    from certstream.watcher import TransparencyWatcher

    loop = asyncio.get_event_loop()
    watcher = TransparencyWatcher(loop)
    webserver = WebServer(loop, watcher)
    asyncio.ensure_future(asyncio.gather(*watcher.get_tasks()))
    webserver.run_server()
