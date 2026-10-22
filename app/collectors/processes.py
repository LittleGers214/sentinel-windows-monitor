import json

import psutil

from app.collectors.network import collect_connections
from app.database.models import utcnow


def collect_processes():
    connections, warning = collect_connections()
    result = []
    now = utcnow()
    for process in psutil.process_iter():
        try:
            if not process.is_running():
                continue
            info = process.as_dict(
                attrs=[
                    "pid",
                    "name",
                    "exe",
                    "create_time",
                    "username",
                    "cpu_percent",
                    "memory_info",
                ],
                ad_value=None,
            )
            result.append(
                {
                    "pid": info["pid"],
                    "process_name": info["name"] or "Недоступно",
                    "executable_path": info["exe"],
                    "started_at": info["create_time"],
                    "username": info["username"],
                    "collected_at": now,
                    "cpu_percent": info["cpu_percent"],
                    "memory_bytes": info["memory_info"].rss if info["memory_info"] else None,
                    "connections": json.dumps(
                        connections.get(info["pid"], []) if not warning else None
                    ),
                }
            )
        except (psutil.Error, OSError):
            continue
    return result, warning
