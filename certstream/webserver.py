import asyncio
import collections
import json
import logging
import os
import time
import ssl
from aiohttp import web
from aiohttp.web_urldispatcher import Response
from aiohttp.web_ws import WebSocketResponse

from certstream.util import pretty_date, get_ip

WebsocketClientInfo = collections.namedtuple(
    "WebsocketClientInfo", ["external_ip", "queue", "connection_time"]
)

STATIC_INDEX = f"""
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
    def __init__(self, _loop, transparency_watcher):
        self.active_sockets = []
        self.recently_seen = collections.deque(maxlen=25)
        self.stats_url = os.getenv("STATS_URL", "stats")
        self.logger = logging.getLogger("certstream.webserver")

        self.loop = _loop
        self.watcher = transparency_watcher

        self.app = web.Application()

        self._add_routes()

    def run_server(self):
        self.loop.create_task(self.mux_ctl_stream())
        self.loop.create_task(self.ws_heartbeats())

        if os.environ.get("NOSSL", False):
            ssl_ctx = None
        else:
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(
                certfile=os.getenv("SERVER_CERT", "server.crt"),
                keyfile=os.getenv("SERVER_KEY", "server.key"),
            )

        self.loop.run_until_complete(
            web._run_app(
                self.app, port=int(os.environ.get("PORT", 8080)), ssl_context=None
            )
        )

    def _add_routes(self):
        self.app.router.add_get("/latest.json", self.latest_json_handler)
        self.app.router.add_get("/example.json", self.example_json_handler)
        self.app.router.add_get(f"/{self.stats_url}", self.stats_handler)
        self.app.router.add_get("/", self.root_handler)
        self.app.router.add_get("/develop", self.dev_handler)

    async def mux_ctl_stream(self):
        while True:
            cert_data = await self.watcher.stream.get()

            data_packet = {"message_type": "certificate_update", "data": cert_data}

            self.recently_seen.append(data_packet)

            for client in self.active_sockets:
                try:
                    client.queue.put_nowait(data_packet)
                except asyncio.QueueFull:
                    pass

    async def dev_handler(self, request):
        # If we have a websocket request
        if request.headers.get("Upgrade"):
            ws = web.WebSocketResponse()

            await ws.prepare(request)

            try:
                for message in self.recently_seen:
                    message_json = json.dumps(message)
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

    async def root_handler(self, request):
        resp = WebSocketResponse()
        available = resp.can_prepare(request)
        if not available:
            return Response(body=STATIC_INDEX, content_type="text/html")

        await resp.prepare(request)

        client_queue = asyncio.Queue(maxsize=500)

        client = WebsocketClientInfo(
            external_ip=get_ip(request),
            queue=client_queue,
            connection_time=int(time.time()),
        )

        try:
            self.logger.info(f"Client {client.external_ip} joined.")
            self.active_sockets.append(client)
            while True:
                message = await client_queue.get()
                message_json = json.dumps(message)
                await resp.send_str(message_json)

        finally:
            self.active_sockets.remove(client)
            self.logger.info(f"Client {client.external_ip} disconnected.")

    async def latest_json_handler(self, _):
        return web.Response(
            body=json.dumps({"messages": list(self.recently_seen)}, indent=4),
            headers={"Access-Control-Allow-Origin": "*"},
            content_type="application/json",
        )

    async def example_json_handler(self, _):
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

    async def stats_handler(self, _):
        clients = {}
        for client in self.active_sockets:
            client_identifier = f"{client.external_ip}-{client.connection_time}"
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

    async def ws_heartbeats(self):
        self.logger.info("Starting WS heartbeat coro...")
        while True:
            await asyncio.sleep(30)
            self.logger.debug("Sending ping...")
            timestamp = time.time()
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
