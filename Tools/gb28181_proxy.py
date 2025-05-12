#!/usr/bin/env python3
"""
GB28181 SIP & PS Stream Transparent Proxy/Recorder
-------------------------------------------------
This updated version not only proxies and logs SIP signaling, it also *captures*
10 seconds of the **raw PS (Program Stream) video** each time the camera starts
streaming.  It works by rewriting the server-side INVITE so the camera sends
its TCP/RTP/PS connection to us first; we record the bytes, then forward them
to the real server in real-time.

Highlights
~~~~~~~~~~
* **Full bidirectional SIP log** (as before).
* **Automatic media proxy** - rewrites SDP and opens a temporary port.
* **10 s PS capture** - saved as ``ps_capture_YYYYMMDD_HHMMSS.ps`` for each
  session.  Size is usually just a few MiB.
* Pure ``asyncio`` implementation; *no extra dependencies*.
* Works for the common GB28181 pattern: server offers *passive* TCP, camera
  answers *active* TCP.

Usage Example
-------------
::

   python3 gb28181_proxy.py \
       --listen-host 0.0.0.0 \
       --listen-port 5060 \
       --server-host xxx.xxx.xxx.xxx \
       --server-port 5060

Options ``--log-file``, ``--max-bytes``, ``--backup-count`` behave the same as
before.
"""
import argparse
import asyncio
import datetime
import logging
import string
import time
from logging.handlers import RotatingFileHandler
from typing import Optional

PRINTABLE = set(bytes(string.printable, "ascii"))

###############################################################################
# Utility helpers
###############################################################################

def setup_logging(path: str, max_bytes: int, backup_count: int):
    logger = logging.getLogger("gb28181.proxy")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            "%Y-%m-%d %H:%M:%S")
    handler = RotatingFileHandler(path, maxBytes=max_bytes,
                                  backupCount=backup_count, encoding="utf-8")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)
    return logger


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(
            chr(b) if b in PRINTABLE and chr(b) not in "\r\n\t" else "."
            for b in chunk
        )
        lines.append(f"{i:08x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)

###############################################################################
# Recorder – grabs N seconds of the PS bytes
###############################################################################

class Recorder:
    """Write the first *duration* seconds of data into *path*."""

    def __init__(self, path: str, duration: int = 10):
        self._file = open(path, "wb")
        self._start = time.monotonic()
        self._duration = duration
        self._closed = False

    def write(self, buf: bytes):
        if self._closed:
            return
        if time.monotonic() - self._start < self._duration:
            self._file.write(buf)
        else:
            self._file.close()
            self._closed = True

###############################################################################
# Core proxy logic
###############################################################################

async def pipe(reader: asyncio.StreamReader,
               writer: asyncio.StreamWriter,
               direction: str,
               logger: logging.Logger,
               src: str,
               dst: str,
               recorder: Optional[Recorder] = None,
               transform=None):
    """Copy all bytes from *reader* to *writer*, with optional transform & record."""
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break

            if transform is not None:
                data = await transform(data)

            if recorder is not None:
                recorder.write(data)

            # Log
            logger.debug("%s %s -> %s %d bytes", direction, src, dst, len(data))
            # Try to pretty‑print SIP text
            try:
                txt = data.decode("utf-8", errors="replace")
                if txt.strip():
                    logger.debug("----- TEXT BEGIN -----\n%s\n----- TEXT END -----", txt)
            except UnicodeDecodeError:
                pass
            # Raw hexdump
            logger.debug("----- HEXDUMP BEGIN -----\n%s\n----- HEXDUMP END -----", hexdump(data))

            writer.write(data)
            await writer.drain()
    except Exception as e:
        logger.error("%s pipe error: %s", direction, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

###############################################################################
# Media handling – rewrite INVITE & bridge the PS TCP stream
###############################################################################

async def media_bridge(camera_reader: asyncio.StreamReader,
                       camera_writer: asyncio.StreamWriter,
                       server_ip: str,
                       server_port: int,
                       logger: logging.Logger,
                       record_seconds: int = 10):
    cam_addr = "%s:%s" % camera_writer.get_extra_info("peername")
    srv_addr = f"{server_ip}:{server_port}"
    logger.info("PS bridge %s -> %s starting", cam_addr, srv_addr)
    try:
        server_reader, server_writer = await asyncio.open_connection(server_ip, server_port)
    except Exception as e:
        logger.error("Failed to connect upstream media %s: %s", srv_addr, e)
        camera_writer.close(); await camera_writer.wait_closed(); return

    # Create recorder – 10‑second PS dump
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    rec_path = f"ps_capture_{ts}.ps"
    recorder = Recorder(rec_path, record_seconds)
    logger.info("Recording first %d s of PS to %s", record_seconds, rec_path)

    await asyncio.gather(
        pipe(camera_reader, server_writer, "PS C2S", logger, cam_addr, srv_addr, recorder=recorder),
        pipe(server_reader, camera_writer, "PS S2C", logger, srv_addr, cam_addr),
    )
    logger.info("PS bridge %s <-> %s closed", cam_addr, srv_addr)

###############################################################################
# Main SIP session handler
###############################################################################

async def handle_client(client_reader: asyncio.StreamReader,
                        client_writer: asyncio.StreamWriter,
                        server_host: str,
                        server_port: int,
                        listen_host: str,
                        logger: logging.Logger):
    client_addr = "%s:%s" % client_writer.get_extra_info("peername")
    logger.info("New camera connection from %s", client_addr)

    try:
        server_reader, server_writer = await asyncio.open_connection(server_host, server_port)
    except Exception as e:
        logger.error("Cannot connect to SIP server %s:%d: %s", server_host, server_port, e)
        client_writer.close(); await client_writer.wait_closed(); return

    server_addr = f"{server_host}:{server_port}"
    logger.info("Proxying %s <-> %s", client_addr, server_addr)

    loop = asyncio.get_running_loop()

    async def transform_s2c(data: bytes) -> bytes:  # noqa: C901 – a bit long but clear
        try:
            txt = data.decode("utf-8", errors="ignore")
        except Exception:
            return data  # not text
        if not txt.lstrip().upper().startswith("INVITE"):
            return data
        # Basic SDP parsing – look for first "c=" & "m=video" lines
        lines = txt.splitlines()
        c_idx, m_idx = None, None
        for i, ln in enumerate(lines):
            if ln.startswith("c=IN IP4 "):
                c_idx = i
            elif ln.startswith("m=video "):
                m_idx = i
        if c_idx is None or m_idx is None:
            return data  # Not what we need
        try:
            server_ip_media = lines[c_idx].split()[2]
            parts = lines[m_idx].split()
            server_port_media = int(parts[1])
        except Exception:
            return data  # Parsing failed

        # Allocate local listening port for media
        media_server = await asyncio.start_server(
            lambda r, w: media_bridge(r, w, server_ip_media, server_port_media, logger),
            host=listen_host,
            port=0,
        )
        local_port = media_server.sockets[0].getsockname()[1]
        local_ip = client_writer.get_extra_info("sockname")[0]
        logger.info("Rewriting SDP: server %s:%d -> proxy %s:%d",
                    server_ip_media, server_port_media, local_ip, local_port)

        # Replace lines
        lines[c_idx] = f"c=IN IP4 {local_ip}"
        parts[1] = str(local_port)
        lines[m_idx] = " ".join(parts)
        modified_txt = "\r\n".join(lines) + "\r\n\r\n"

        # Start media server
        asyncio.create_task(media_server.serve_forever())
        return modified_txt.encode()

    # Run two direction pipes; S2C uses transform to intercept INVITE/SDP
    await asyncio.gather(
        pipe(client_reader, server_writer, "C2S", logger, client_addr, server_addr),
        pipe(server_reader, client_writer, "S2C", logger, server_addr, client_addr,
             transform=transform_s2c),
    )
    logger.info("Session %s <-> %s closed", client_addr, server_addr)

###############################################################################
# Program entry‑point
###############################################################################

async def main():
    parser = argparse.ArgumentParser(description="Transparent GB28181 SIP & PS proxy/recorder")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Local host to bind for SIP")
    parser.add_argument("--listen-port", type=int, default=5060, help="Local SIP port")
    parser.add_argument("--server-host", default="111.111.111.111", help="Upstream SIP server host")
    parser.add_argument("--server-port", type=int, default=25060, help="Upstream SIP server port")
    parser.add_argument("--log-file", default="gb28181_proxy.log", help="Path to log file")
    parser.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024, help="Rotate log after N bytes")
    parser.add_argument("--backup-count", type=int, default=3, help="Number of rotated logs to keep")
    args = parser.parse_args()

    logger = setup_logging(args.log_file, args.max_bytes, args.backup_count)
    logger.info("GB28181 proxy starting. SIP %s:%d -> upstream %s:%d",
                args.listen_host, args.listen_port, args.server_host, args.server_port)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w,
                                   args.server_host, args.server_port,
                                   args.listen_host, logger),
        host=args.listen_host,
        port=args.listen_port,
    )

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.getLogger("gb28181.proxy").info("Proxy terminated by user")

