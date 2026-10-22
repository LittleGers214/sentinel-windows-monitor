import psutil


def collect_connections():
    try:
        result = {}
        for connection in psutil.net_connections(kind="inet"):

            def address(item):
                return f"{item.ip}:{item.port}" if item else "—"

            result.setdefault(connection.pid, []).append(
                {
                    "local": address(connection.laddr),
                    "remote": address(connection.raddr),
                    "status": connection.status,
                }
            )
        return result, None
    except (psutil.Error, OSError) as exc:
        return {}, f"Сетевые соединения недоступны: {exc}"
