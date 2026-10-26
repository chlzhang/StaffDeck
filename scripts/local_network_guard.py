"""Network guard for local synthetic regression tests."""
import ipaddress
import json
import os
import socket
from pathlib import Path

_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex
blocked = []


def is_local(sock, address):
    if sock.family == socket.AF_UNIX:
        return True
    host = str(address[0]).lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def local_connect(sock, address):
    if not is_local(sock, address):
        blocked.append({"family": int(sock.family), "host": str(address[0])})
        raise OSError("External connections are blocked during isolated validation")
    return _connect(sock, address)


def local_connect_ex(sock, address):
    if not is_local(sock, address):
        blocked.append({"family": int(sock.family), "host": str(address[0])})
        raise OSError("External connections are blocked during isolated validation")
    return _connect_ex(sock, address)


def pytest_sessionstart(session):
    socket.socket.connect = local_connect
    socket.socket.connect_ex = local_connect_ex


def pytest_sessionfinish(session, exitstatus):
    socket.socket.connect = _connect
    socket.socket.connect_ex = _connect_ex
    report = Path(os.environ.get("STAFFDECK_NETWORK_GUARD_REPORT", ".dev/local-smoke/network-guard.json"))
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps({"blocked_connections": blocked, "count": len(blocked)}, indent=2) + "\n"
    )
