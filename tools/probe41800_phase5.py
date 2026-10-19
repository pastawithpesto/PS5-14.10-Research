#!/usr/bin/env python3
"""Port 41800 Phase 5: Command brute-force.

The server expects a specific command word as the first token.
All standard HTTP methods return "Bad request: [METHOD]".
Format: COMMAND path\r\n\r\n (no HTTP version string).
Brute-forcing common protocol commands.
"""
import argparse
import socket
import time
import datetime
import os


def make_logger(log_path):
    def log(line=""):
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return log


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def banner(log, title):
    log()
    log("=" * 78)
    log(f"== {title}")
    log("=" * 78)


def quick_probe(host, port, timeout, inter_sleep, name, request_bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        s.sendall(request_bytes)
        data = b""
        try:
            while len(data) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        rt = (time.time() - t0) * 1000
        s.close()
        return data, rt
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None, 0
    finally:
        time.sleep(inter_sleep)


COMMANDS = [
    "SUBSCRIBE", "UNSUBSCRIBE", "NOTIFY", "M-SEARCH", "M-POST",
    "DESCRIBE", "ANNOUNCE", "SETUP", "TEARDOWN", "RECORD",
    "REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "REFER", "MESSAGE", "UPDATE", "PRACK",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
    "SRCH", "WAKEUP", "LAUNCH", "STANDBY", "DDP", "PS", "PSN", "SIE",
    "SPIRC", "MERCURY", "HERMES", "AUTH", "LOGIN", "HELLO", "HANDSHAKE",
    "PAIR", "UNPAIR", "SYNC", "TRANSFER", "RESOLVE",
    "RPC", "CALL", "CMD", "EXEC", "RUN", "QUERY", "FETCH",
    "SEND", "RECV", "PUSH", "PULL", "EVENT", "EMIT",
    "OPEN", "CLOSE", "START", "STOP", "STATUS", "CHECK", "PING", "PONG",
    "LINK", "UNLINK", "BIND", "UNBIND", "ATTACH", "DETACH",
    "LIST", "SET", "ADD", "REMOVE", "RESET", "CLEAR",
    "DATA", "STREAM", "CHUNK", "FRAME",
    "getInfo", "addUser", "removeUser", "resetUsers", "getMetadata",
    "GetInfo", "AddUser", "RemoveUser", "ResetUsers", "GetMetadata",
    "GETINFO", "ADDUSER", "REMOVEUSER", "RESETUSERS", "GETMETADATA",
    "get_info", "add_user", "remove_user", "reset_users", "get_metadata",
    "COMPANION", "SECOND_SCREEN", "MEDIA", "REMOTE",
    "JSON-RPC", "JSONRPC", "XML-RPC", "XMLRPC",
]


def main():
    parser = argparse.ArgumentParser(description="Port 41800 Phase 5: Command brute-force")
    parser.add_argument("--ps5-ip", required=True, help="PS5 IP address")
    parser.add_argument("--port", type=int, default=41800)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    host = args.ps5_ip
    port = args.port
    timeout = 3.0
    inter_sleep = 0.5
    log_path = args.log or os.path.join(os.getcwd(), "port41800-phase5.log")
    log = make_logger(log_path)

    banner(log, f"PORT 41800 PHASE 5: COMMAND BRUTE FORCE  {host}:{port}  {ts()}")
    log(f"Testing {len(COMMANDS)} command words")

    results = []
    for cmd in COMMANDS:
        req = f"{cmd} /\r\n\r\n".encode("ascii", "replace")
        data, rt = quick_probe(host, port, timeout, inter_sleep, cmd, req)
        if data is None:
            status = "ERR"
            body_short = ""
        elif len(data) == 0:
            if rt > 2000:
                status = "HELD"
            else:
                status = "CLOSE"
            body_short = ""
        else:
            try:
                body = data.decode("utf-8", "replace")
            except Exception:
                body = data.hex()[:60]
            if "Bad request" in body:
                status = "BAD_REQ"
            elif "500" in body:
                status = "500"
            elif "200" in body:
                status = "200_OK"
            elif "404" in body:
                status = "404"
            elif "403" in body:
                status = "403"
            elif "400" in body:
                status = "400"
            elif "401" in body:
                status = "401"
            else:
                status = f"RESP_{len(data)}B"
            body_short = body.split("\r\n\r\n")[-1].strip()[:60] if body else ""

        results.append((cmd, status, len(data) if data else 0, body_short))

        if status not in ("BAD_REQ", "500", "HELD", "CLOSE", "ERR"):
            log(f"  *** HIT: {cmd} -> {status} ({len(data)} bytes) ***")
            log(f"    {body_short}")

    banner(log, "FULL RESULTS")
    for cmd, status, sz, body_short in results:
        if status == "BAD_REQ":
            continue
        log(f"  {cmd:20s} {status:10s} {sz:4d}B  {body_short}")

    banner(log, "BAD_REQ methods (expected)")
    bad = [r[0] for r in results if r[1] == "BAD_REQ"]
    log(f"  {', '.join(bad)}")

    banner(log, f"DONE  {ts()}")
    print(f"Done. Log: {log_path}")


if __name__ == "__main__":
    main()
