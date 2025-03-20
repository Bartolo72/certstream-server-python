from datetime import datetime, timedelta
from aiohttp.web_urldispatcher import Response


def pretty_date(time: bool | int | datetime = False) -> str:
    """
    Get a datetime object or a int() Epoch timestamp and return a
    pretty string like 'an hour ago', 'Yesterday', '3 months ago',
    'just now', etc
    """
    now: datetime = datetime.now()
    diff: timedelta
    if type(time) is int:
        diff = now - datetime.fromtimestamp(time)
    elif isinstance(time, datetime):
        diff = now - time
    elif not time:
        diff = now - now
    second_diff: int = diff.seconds
    day_diff: int = diff.days

    if day_diff < 0:
        return ""

    if day_diff == 0:
        if second_diff < 10:
            return "just now"
        if second_diff < 60:
            return str(second_diff) + " seconds ago"
        if second_diff < 120:
            return "a minute ago"
        if second_diff < 3600:
            return str(second_diff / 60) + " minutes ago"
        if second_diff < 7200:
            return "an hour ago"
        if second_diff < 86400:
            return str(second_diff / 3600) + " hours ago"
    if day_diff == 1:
        return "Yesterday"
    if day_diff < 7:
        return str(day_diff) + " days ago"
    if day_diff < 31:
        return str(day_diff / 7) + " weeks ago"
    if day_diff < 365:
        return str(day_diff / 30) + " months ago"
    return str(day_diff / 365) + " years ago"


def get_ip(request: Response) -> str:
    peer_info = request.transport.get_extra_info("peername")

    ip = "UNKNOWN"
    if peer_info is not None:
        ip, _, __, ___ = peer_info

    if "X-Forwarded-For" in request.headers:
        ip = request.headers.get("X-Forwarded-For")

    return ip
