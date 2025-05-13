#!/usr/bin/env python3
"""gb28181_pusher — GB28181 signaling + test‑stream helper

Tested on Python 3.9 / Ubuntu 22.04.

Usage example
─────────────

python3 gb28181_pusher.py \
    --server-ip 192.168.1.100 --server-port 5060 \
    --server-id 11009000000000000000 --domain 1100900000 \
    --agent-id 300000000010000000000 --agent-password 000000 \
    --channel-id 340000000000000000000 \
    --source "rtsp://admin:admin@192.168.111.222/h264/ch1/main/av_stream" \
    --verbose

"""
from __future__ import annotations

import argparse
import hashlib
import logging
import random
import re
import shlex
import socket
import subprocess
import threading
import time
from contextlib import AbstractContextManager
from typing import Callable, List, Optional, Tuple

LOGGER = logging.getLogger("gb28181")

MANUFACTURER = "StrawberryInno"
DEVICENAME  = "Superdock"

###############################################################################
# ───────────────────────────── Helper utilities ───────────────────────────── #
###############################################################################

def md5_hex(text: str) -> str:
    """Return ``MD5(text).hexdigest()`` using explicit *UTF‑8* encoding."""
    return hashlib.md5(text.encode("utf‑8")).hexdigest()


def find_local_ip(dst: str) -> str:
    """Return the source IPv4 address the kernel would use to reach *dst*."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((dst, 80))  # arbitrary remote port
        return sock.getsockname()[0]
    finally:
        sock.close()


###############################################################################
# ────────────────────────────── Core class API ────────────────────────────── #
###############################################################################

class GB28181Pusher(AbstractContextManager):
    """A tiny GB28181 device implementation that answers *INVITE* and pushes a
    synthetic test stream (via *gst‑launch‑1.0*) to the requested RTP/PS port.
    """

    # Reasonable protocol defaults — can be overridden at construction time
    HB_GAP: int = 60      # seconds between keep‑alives
    REG_TRIES: int = 5    # REGISTER retry attempts
    RECV_TIMEOUT: int = 5 # UDP rx timeout (seconds)

    # SDP payload type priorities when *m=video* advertises several
    _PT_PRIORITY: Tuple[Tuple[int, str], ...] = ((96, "PS"), (98, "H264"))

    # ---------------------------------------------------------------------
    # Construction / context‑manager helpers
    # ---------------------------------------------------------------------
    def __init__(
        self,
        *,
        server_ip: str,
        server_port: int = 5060,
        server_id: str,
        domain: Optional[str] = None,
        agent_id: str,
        agent_password: str,
        channel_id: str,
        source: str = "test",
        use_udp_signalling: bool = False,
        local_ip: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        self.server_ip: str = server_ip
        self.server_port: int = server_port
        self.server_id: str = server_id
        self.domain: str = domain or server_id[:10]
        self.agent_id: str = agent_id
        self.source: str = source
        self.agent_password: str = agent_password
        self.channel_id: str = channel_id
        self.use_udp_signalling: bool = use_udp_signalling
        self.local_ip: str = local_ip or find_local_ip(server_ip)
        self.verbose: bool = verbose

        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            format="[%(asctime)s] %(levelname)s — %(message)s",
            datefmt="%H:%M:%S",
            level=log_level,
        )

        self._sock: socket.socket | None = None
        self._send: Callable[[bytes], None]
        self._recv: Callable[[], str]

        # Data associated with the current media session
        self._push_thread: Optional[threading.Thread] = None
        self._push_stop_evt: Optional[threading.Event] = None

    # ------------------------------------------------------------
    # Public top‑level entry point
    # ------------------------------------------------------------
    def run_forever(self) -> None:
        """Open signalling socket, REGISTER to the platform, then handle
        requests forever (``Ctrl‑C`` or :pyclass:`KeyboardInterrupt` to stop).
        """
        self._open_signalling_socket()
        self._register()  # raises on failure
        self._start_heartbeat()
        LOGGER.info("Ready — waiting for INVITE/SUBSCRIBE")
        self._event_loop()

    # Context‑manager helpers so callers can ``with GB28181Pusher(...):``
    def __enter__(self):
        self.run_forever()  # blocks until KeyboardInterrupt / exception
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: D401,D401
        self._shutdown()
        return False  # do *not* suppress exceptions

    # ------------------------------------------------------------------
    # SIP helpers (REGISTER / MESSAGE / 200 OK / etc.)
    # ------------------------------------------------------------------
    def _digest_response(
        self,
        nonce: str,
        realm: str,
        method: str,
        uri: str,
        qop: Optional[str],
    ) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
        """Return ``(response, nc, cnonce, qop_used)`` for a *Digest* challenge."""
        a1 = md5_hex(f"{self.agent_id}:{realm}:{self.agent_password}")
        a2 = md5_hex(f"{method}:{uri}")
        if qop:  # RFC 2617
            nc = "00000001"
            cnonce = f"{random.randint(0, 0xFFFFFF):06x}"
            resp = md5_hex(f"{a1}:{nonce}:{nc}:{cnonce}:{qop}:{a2}")
            return resp, nc, cnonce, qop
        # RFC 2069
        resp = md5_hex(f"{a1}:{nonce}:{a2}")
        return resp, None, None, None

    # Sip‑message helper: start‑line • headers[] • body
    @staticmethod
    def _sip(start_line: str, headers: List[str], body: str = "") -> bytes:
        headers.append(f"Content-Length: {len(body)}")
        return (start_line + "\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body).encode()

    # ----- REGISTER helpers -------------------------------------------------
    def _build_register(self, cseq: int, auth_header: Optional[str] = None) -> bytes:
        via_branch = f"z9hG4bK{time.time_ns()}"
        hdrs = [
            f"Via: SIP/2.0/{'UDP' if self.use_udp_signalling else 'TCP'} {self.local_ip}:{self._local_port};branch={via_branch}",
            f"From: <sip:{self.agent_id}@{self.domain}>;tag=reg",
            f"To: <sip:{self.agent_id}@{self.domain}>",
            f"Call-ID: {self.agent_id}",
            f"CSeq: {cseq} REGISTER",
            f"Contact: <sip:{self.agent_id}@{self.local_ip}:{self._local_port}>;+sip.instance=\"<urn:uuid:{self.agent_id}>\"",
            "Max-Forwards: 70",
            "User-Agent: sbgb28181",
            "Expires: 3600",
        ]
        if auth_header:
            hdrs.append(f"Authorization: {auth_header}")
        return self._sip(f"REGISTER sip:{self.domain} SIP/2.0", hdrs)

    # ----- MESSAGE helpers --------------------------------------------------
    def _build_message(self, xml_body: str, cseq: int, suffix: str) -> bytes:
        hdrs = [
            f"Via: SIP/2.0/{'UDP' if self.use_udp_signalling else 'TCP'} {self.local_ip}:{self._local_port};branch=z9hG4bK{time.time_ns()}",
            f"From: <sip:{self.agent_id}@{self.domain}>;tag=resp",
            f"To: <sip:{self.server_id}@{self.domain}>",
            f"Call-ID: {self.agent_id}{suffix}",
            f"CSeq: {cseq} MESSAGE",
            "Content-Type: Application/MANSCDP+xml",
            "Max-Forwards: 70",
            "User-Agent: sbgb28181",
        ]
        return self._sip(f"MESSAGE sip:{self.server_id}@{self.domain} SIP/2.0", hdrs, xml_body)

    # ----- Generic 200 OK for BYE / MESSAGE etc. ----------------------------
    def _ok200(self, req: str) -> bytes:
        via = re.search(r"Via:(.*)", req).group(1).strip()
        fr = re.search(r"From:(.*)", req).group(1).strip()
        to = re.search(r"To:(.*)", req).group(1).strip()
        call = re.search(r"Call-ID:(.*)", req).group(1).strip()
        cseq = re.search(r"CSeq:(.*)", req).group(1).strip()
        hdrs = [
            f"Via:{via}",
            f"From:{fr}",
            f"To:{to}",
            f"Call-ID:{call}",
            f"CSeq:{cseq}",
            f"Contact: <sip:{self.agent_id}@{self.local_ip}:{self._local_port}>",
            "User-Agent: sbgb28181",
        ]
        return self._sip("SIP/2.0 200 OK", hdrs)

    # ----- INVITE 200 OK (SDP) ---------------------------------------------
    def _invite_ok(
        self,
        invite_msg: str,
        dst_ip: str,
        dst_port: int,
        pt: int,
        is_tcp: bool,
        codec: str,
        ssrc_dec: Optional[int],
    ) -> bytes:
        """Craft 200 OK with SDP that mirrors platform's *c= / m=* lines."""
        via = re.search(r"Via:(.*)", invite_msg).group(1).strip()
        fr = re.search(r"From:(.*)", invite_msg).group(1).strip()
        to = re.search(r"To:(.*)", invite_msg).group(1).strip()
        if "tag=" not in to:
            to += ";tag=ok"
        call = re.search(r"Call-ID:(.*)", invite_msg).group(1).strip()
        cseq = re.search(r"CSeq:(.*)", invite_msg).group(1).strip()

        sdp_lines = [
            "v=0",
            f"o={self.agent_id} 0 0 IN IP4 {self.local_ip}",
            "s=Play",
            f"c=IN IP4 {dst_ip}",
            "t=0 0",
            f"m=video {dst_port} {'TCP/RTP/AVP' if is_tcp else 'RTP/AVP'} {pt}",
            "a=sendonly",
            f"a=rtpmap:{pt} {codec}/90000",
            "a=filesize:0",
        ]
        if is_tcp:
            sdp_lines.insert(6, "a=setup:active")
            sdp_lines.insert(7, "a=connection:new")
        if ssrc_dec is not None:
            sdp_lines.append(f"y={ssrc_dec:010d}")

        sdp_body = "\r\n".join(sdp_lines) + "\r\n"
        hdrs = [
            f"Via:{via}",
            f"From:{fr}",
            f"To:{to}",
            f"Call-ID:{call}",
            f"CSeq:{cseq}",
            f"Contact: <sip:{self.agent_id}@{self.local_ip}:{self._local_port}>",
            "Content-Type: application/sdp",
            "User-Agent: sbgb28181",
        ]
        return self._sip("SIP/2.0 200 OK", hdrs, sdp_body)

    # ----- SUBSCRIBE 200 OK -------------------------------------------------
    def _sub_ok(self, req: str) -> bytes:
        via = re.search(r"Via:(.*)", req).group(1).strip()
        fr = re.search(r"From:(.*)", req).group(1).strip()
        to = re.search(r"To:(.*)", req).group(1).strip()
        if "tag=" not in to:
            to += f";tag={random.randint(1,1<<31)}"
        call = re.search(r"Call-ID:(.*)", req).group(1).strip()
        cseq = re.search(r"CSeq:(.*)", req).group(1).strip()
        ev_id = re.search(r"Event:\s*Catalog;id=(\d+)", req).group(1)
        sn = re.search(r"<SN>(\d+)</SN>", req).group(1)

        body = (
            f"<?xml version='1.0' encoding='GB2312'?><Response><CmdType>Catalog</CmdType>"
            f"<SN>{sn}</SN><DeviceID>{self.agent_id}</DeviceID><Result>OK</Result></Response>"
        )
        hdrs = [
            f"Via:{via}",
            f"From:{fr}",
            f"To:{to}",
            f"Call-ID:{call}",
            f"CSeq:{cseq}",
            f"Contact:<sip:{self.agent_id}@{self.local_ip}:{self._local_port}>",
            "Expires: 600",
            "Content-Type: Application/MANSCDP+xml",
            f"Event: Catalog;id={ev_id}",
            "User-Agent: sbgb28181",
        ]
        return self._sip("SIP/2.0 200 OK", hdrs, body)

    # ------------------------------------------------------------------
    # Signalling socket helpers
    # ------------------------------------------------------------------
    def _open_signalling_socket(self) -> None:
        if self.use_udp_signalling:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.local_ip, 0))
            sock.settimeout(self.RECV_TIMEOUT)
            LOGGER.info("UDP signalling %s → %s:%d", sock.getsockname(), self.server_ip, self.server_port)
            self._send = self._wrap_send(lambda d: sock.sendto(d, (self.server_ip, self.server_port)), "UDP→")
            self._recv = self._wrap_recv(lambda: sock.recvfrom(65535)[0].decode(), "UDP←")
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_ip, self.server_port))
            LOGGER.info("TCP signalling %s → %s:%d", sock.getsockname(), self.server_ip, self.server_port)
            self._send = self._wrap_send(sock.sendall, "TCP→")
            self._recv = self._wrap_recv(lambda: self._recv_tcp(sock), "TCP←")
        self._sock = sock
        self._local_port = sock.getsockname()[1]

    # Send/recv wrappers with optional verbose dump
    def _wrap_send(self, fn: Callable[[bytes], None], label: str) -> Callable[[bytes], None]:
        def _inner(data: bytes):
            if self.verbose:
                LOGGER.debug("%s\n%s", label, data.decode(errors="ignore"))
            fn(data)
        return _inner

    def _wrap_recv(self, fn: Callable[[], str], label: str) -> Callable[[], str]:
        def _inner() -> str:
            data = fn()
            if self.verbose:
                LOGGER.debug("%s\n%s", label, data)
            return data
        return _inner

    # ------------------------------------------------------------------
    # REGISTER / keep‑alive
    # ------------------------------------------------------------------
    def _register(self) -> None:
        cseq = 1
        for attempt in range(self.REG_TRIES):
            self._send(self._build_register(cseq))
            try:
                rsp = self._recv()
            except socket.timeout:
                LOGGER.warning("REGISTER timeout (%d/%d)", attempt+1, self.REG_TRIES)
                continue
            if rsp.startswith("SIP/2.0 401"):
                nonce = re.search(r'nonce="([^"]+)"', rsp).group(1)
                realm = re.search(r'realm="([^"]+)"', rsp).group(1)
                qop_m = re.search(r'qop\s*=\s*"?([a-zA-Z0-9\-]+)', rsp)
                qop = qop_m.group(1) if qop_m else None
                resp, nc, cnonce, qop_used = self._digest_response(nonce, realm, "REGISTER", f"sip:{self.domain}", qop)
                cseq += 1
                if qop_used:
                    auth_hdr = (
                        f'Digest username="{self.agent_id}", realm="{realm}", nonce="{nonce}",'  # noqa: E501
                        f' uri="sip:{self.domain}", response="{resp}", algorithm=MD5,'
                        f' qop={qop_used}, nc={nc}, cnonce="{cnonce}"'
                    )
                else:
                    auth_hdr = (
                        f'Digest username="{self.agent_id}", realm="{realm}", nonce="{nonce}",'  # noqa: E501
                        f' uri="sip:{self.domain}", response="{resp}", algorithm=MD5'
                    )
                self._send(self._build_register(cseq, auth_hdr))
                rsp = self._recv()
            if rsp.startswith("SIP/2.0 200"):
                LOGGER.info("REGISTER success")
                break
        else:
            raise RuntimeError("Failed to REGISTER after %d attempts" % self.REG_TRIES)

        # --- Send initial INFO / CATALOG / KEEPALIVE --------------------
        info_xml = (
            f"<?xml version='1.0' encoding='GB2312'?><Response>"
            f"<CmdType>DeviceInfo</CmdType><SN>1</SN><DeviceID>{self.agent_id}</DeviceID>"
            f"<DeviceName>{DEVICENAME}</DeviceName><Manufacturer>{MANUFACTURER}</Manufacturer>"
            f"<Model>test</Model><Firmware>1.0</Firmware><Result>OK</Result></Response>"
        )
        cat_xml = lambda sn: (
            f"<?xml version='1.0' encoding='GB2312'?><Response><CmdType>Catalog</CmdType><SN>{sn}</SN>"
            f"<DeviceID>{self.agent_id}</DeviceID><SumNum>1</SumNum><DeviceList><Item>"
            f"<DeviceID>{self.channel_id}</DeviceID><Name>ch1</Name><Manufacturer>{MANUFACTURER}</Manufacturer>"
            f"<Model>v1</Model><Status>ON</Status></Item></DeviceList></Response>"
        )
        keep_xml = (
            f"<?xml version='1.0' encoding='GB2312'?><Notify><CmdType>Keepalive</CmdType><SN>1</SN>"
            f"<DeviceID>{self.agent_id}</DeviceID><Status>OK</Status></Notify>"
        )
        self._send(self._build_message(keep_xml, 1, "keep"))
        self._send(self._build_message(info_xml, 2, "info"))
        self._send(self._build_message(cat_xml(1), 3, "cat"))

    # ------------------------------------------------------------------
    # Heart‑beat thread
    # ------------------------------------------------------------------
    def _start_heartbeat(self):
        def _hb():
            seq = 10
            keep_xml = (
                f"<?xml version='1.0' encoding='GB2312'?><Notify><CmdType>Keepalive</CmdType><SN>{{}}</SN>"
                f"<DeviceID>{self.agent_id}</DeviceID><Status>OK</Status></Notify>"
            )
            while True:
                time.sleep(self.HB_GAP)
                self._send(self._build_message(keep_xml.format(seq), seq, "k"))
                seq += 1
        threading.Thread(target=_hb, daemon=True).start()

    # ------------------------------------------------------------------
    # Main receive loop
    # ------------------------------------------------------------------
    def _event_loop(self):
        while True:
            try:
                pkt = self._recv()
            except socket.timeout:
                continue
            except Exception as exc:
                LOGGER.exception("Receive error — leaving main loop: %s", exc)
                break

            if pkt.startswith("INVITE"):
                self._handle_invite(pkt)
            elif pkt.startswith("BYE"):
                self._send(self._ok200(pkt))
                self._stop_push()
                LOGGER.info("Session closed — waiting for next INVITE …")
            elif pkt.startswith("MESSAGE"):
                self._handle_message(pkt)
            elif pkt.startswith("SUBSCRIBE"):
                self._send(self._sub_ok(pkt))

    # ----- INVITE handling --------------------------------------------------
    def _handle_invite(self, invite_msg: str):
        # 100 Trying first
        via = re.search(r"Via:(.*)", invite_msg).group(1).strip()
        fr = re.search(r"From:(.*)", invite_msg).group(1).strip()
        to = re.search(r"To:(.*)", invite_msg).group(1).strip()
        call = re.search(r"Call-ID:(.*)", invite_msg).group(1).strip()
        cseq = re.search(r"CSeq:(.*)", invite_msg).group(1).strip()
        self._send(self._sip("SIP/2.0 100 Trying", [f"Via:{via}", f"From:{fr}", f"To:{to}", f"Call-ID:{call}", f"CSeq:{cseq}"]))

        try:
            dst_ip, dst_port, pt, is_tcp, ssrc_dec, codec = self._parse_invite(invite_msg)
        except ValueError as exc:
            LOGGER.warning("Could not parse SDP in INVITE: %s — ignored", exc)
            return

        self._send(self._invite_ok(invite_msg, dst_ip, dst_port, pt, is_tcp, codec, ssrc_dec))
        _ = self._recv()  # wait for ACK

        self._start_push(dst_ip, dst_port, is_tcp, codec, pt, ssrc_dec)

    # ----- MESSAGE handling -------------------------------------------------
    def _handle_message(self, msg: str):
        self._send(self._ok200(msg))
        if "<Query>" in msg:
            cmd = re.search(r"<CmdType>(.+?)</CmdType>", msg).group(1)
            sn = re.search(r"<SN>(\d+)</SN>", msg).group(1)
            if cmd == "Catalog":
                cat_xml = (
                    f"<?xml version='1.0' encoding='GB2312'?><Response><CmdType>Catalog</CmdType>"
                    f"<SN>{sn}</SN><DeviceID>{self.agent_id}</DeviceID><SumNum>1</SumNum><DeviceList><Item>"
                    f"<DeviceID>{self.channel_id}</DeviceID><Name>ch1</Name><Manufacturer>{MANUFACTURER}</Manufacturer>"
                    f"<Model>v1</Model><Status>ON</Status></Item></DeviceList></Response>"
                )
                self._send(self._build_message(cat_xml, 99, "catR"))
            elif cmd == "DeviceInfo":
                info_xml = (
                    f"<?xml version='1.0' encoding='GB2312'?><Response>"
                    f"<CmdType>DeviceInfo</CmdType><SN>{sn}</SN><DeviceID>{self.agent_id}</DeviceID>"
                    f"<DeviceName>{DEVICENAME}</DeviceName><Manufacturer>{MANUFACTURER}</Manufacturer>"
                    f"<Model>test</Model><Firmware>1.0</Firmware><Result>OK</Result></Response>"
                )
                self._send(self._build_message(info_xml, 98, "infoR"))

    # ------------------------------------------------------------------
    # Media pushing helpers (GStreamer)
    # ------------------------------------------------------------------
    def _start_push(
        self,
        dst_ip: str,
        dst_port: int,
        use_tcp: bool,
        codec: str,
        pt: int,
        ssrc_dec: Optional[int],
    ) -> None:
        # stop any previous
        self._stop_push()

        self._push_stop_evt = threading.Event()
        self._push_thread = threading.Thread(
            target=self._gst_loop,
            args=(dst_ip, dst_port, use_tcp, codec, pt, ssrc_dec, self._push_stop_evt),
            daemon=True,
        )
        self._push_thread.start()

    def _gst_loop(
            self,
            dst_ip: str,
            dst_port: int,
            use_tcp: bool,
            codec: str,
            pt: int,
            ssrc_dec: Optional[int],
            stop_evt: threading.Event
        ) -> None:
        gst_cmd = self._make_gst_cmd(dst_ip, dst_port, use_tcp, codec, pt, ssrc_dec)
        LOGGER.info("GStreamer cmd: %s", shlex.join(gst_cmd))
        proc = subprocess.Popen(gst_cmd)
        try:
            while not stop_evt.is_set():
                time.sleep(1)
        finally:
            proc.terminate()
            proc.wait()
            LOGGER.info("GStreamer exited")

    # Build src part based on self.source
    def _source_elements(self) -> List[str]:
        uri = self.source
        if uri == "test":
            return ["videotestsrc", "is-live=true",
                    "!", "video/x-raw,width=640,height=480,framerate=25/1",
                    "!", "x264enc", "key-int-max=50", "tune=zerolatency", "bitrate=500"]
            # return ["videotestsrc", "is-live=true"]
        if uri.startswith("rtsp://"):
            return ["rtspsrc", f"location={uri}", "latency=0", "!", "rtph264depay"]
        if uri.startswith("udp://"):
            # udp://192.168.111.222:5000 or udp://:5000
            loc = uri[6:]
            host, _, port = loc.partition(":")
            elements = ["udpsrc", f"port={port}"]
            if host:
                elements += [f"multicast-group={host}"]
            elements += ["!", "application/x-rtp", "!", "rtph264depay"]
            return elements
        if uri.startswith("file://"):
            path = uri[7:]
            return ["filesrc", f"location={path}", "!", "qtdemux", "name=demux", "demux.video_0"]
        if uri.startswith("v4l2://"):
            dev = uri[7:]
            return ["v4l2src", f"device={dev}"]
        raise ValueError(f"Unsupported --source URI: {uri}")

    def _make_gst_cmd(
            self,
            dst_ip: str,
            dst_port: int,
            use_tcp: bool,
            codec: str,
            pt: int,
            ssrc_dec: Optional[int]
    ) -> List[str]:
        protocol = "tcp" if use_tcp else "udp"
        ssrc_opt: List[str] = [] if ssrc_dec is None else [f"ssrc=0x{ssrc_dec:08x}"]
        src_chain = self._source_elements()

        if codec == "PS":  # mux to PS
            pay_chain = [
                "!", "h264parse", "!", "mpegpsmux",
                "!", "gb28181sink", f"protocol={protocol}", f"host={dst_ip}", f"port={dst_port}", f"pt={pt}", *ssrc_opt,
            ]
        else:  # elementary H.264 -> RTP
            pay_chain = [
                "!", "videoconvert", "!", "x264enc", "key-int-max=50", "tune=zerolatency", "bitrate=800",
                "!", "rtph264pay", "config-interval=-1", f"pt={pt}",
                "!", "gb28181sink", f"protocol={protocol}", f"host={dst_ip}", f"port={dst_port}", *ssrc_opt,
            ]
        return ["gst-launch-1.0", "-q", *src_chain, *pay_chain]

    def _stop_push(self):
        if self._push_stop_evt is not None:
            self._push_stop_evt.set()
            self._push_thread.join()
            self._push_thread = None
            self._push_stop_evt = None

    # ------------------------------------------------------------------
    # SIP RX helpers: TCP framing & SDP parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _recv_tcp(sock: socket.socket) -> str:
        """Read exactly one SIP message from *sock* (TCP-framed with CRLFCRLF)."""
        buf = b""
        # 1) read until blank line marks end of header
        while True:
            if b"\r\n\r\n" in buf:
                hdr_bin, rest = buf.split(b"\r\n\r\n", 1)
                break
            if b"\n\n" in buf:  # some platforms send LF‑only
                hdr_bin, rest = buf.split(b"\n\n", 1)
                break
            chunk = sock.recv(8192)
            if not chunk:
                raise ConnectionError("TCP closed before header complete")
            buf += chunk
        hdr = hdr_bin.decode(errors="ignore")

        # 2) read body per Content‑Length
        m = re.search(r"Content-Length\s*:\s*(\d+)", hdr, re.I)
        need = int(m.group(1)) if m else 0
        body = rest
        while len(body) < need:
            chunk = sock.recv(need - len(body))
            if not chunk:
                raise ConnectionError("TCP closed before body complete")
            body += chunk

        # 3) return header + CRLFCRLF + body (consistent delimiter)
        return hdr + "\r\n\r\n" + body[:need].decode(errors="ignore")

    def _parse_invite(self, msg: str) -> Tuple[str, int, int, bool, Optional[int], str]:
        """Return (*dst_ip*, *dst_port*, *pt*, *is_tcp*, *ssrc*, *codec*)."""
        # split SDP body
        if "\r\n\r\n" in msg:
            body = msg.split("\r\n\r\n", 1)[1]
        elif "\n\n" in msg:
            body = msg.split("\n\n", 1)[1]
        else:
            raise ValueError("SDP not found in INVITE")

        dst_ip: Optional[str] = None
        dst_port: Optional[int] = None
        is_tcp = False
        cand_list: List[int] = []
        pt_map: dict[int, str] = {}
        ssrc_dec: Optional[int] = None

        for line in body.splitlines():
            l = line.strip()
            if l.startswith("c=IN IP4"):
                dst_ip = l.split()[2]
            elif l.startswith("m=video"):
                sp = l.split()
                dst_port = int(sp[1])
                is_tcp = sp[2].upper().startswith("TCP")
                cand_list = [int(x) for x in sp[3:]]
            elif l.lower().startswith("a=rtpmap:"):
                n, enc = l.split()[0][9:], l.split()[1].split("/")[0]
                pt_map[int(n)] = enc.upper()
            elif l.startswith("y="):
                try:
                    ssrc_dec = int(l[2:])
                except ValueError:
                    pass

        if not cand_list:
            raise ValueError("m=video line not found")

        # choose payload type based on preference list
        for want_pt, want_codec in self._PT_PRIORITY:
            if want_pt in cand_list and pt_map.get(want_pt) == want_codec:
                return dst_ip, dst_port, want_pt, is_tcp, ssrc_dec, want_codec
        # fallback to first announced
        pt = cand_list[0]
        return dst_ip, dst_port, pt, is_tcp, ssrc_dec, pt_map.get(pt, "H264")

    # ------------------------------------------------------------------
    # House‑keeping
    # ------------------------------------------------------------------
    def _shutdown(self):
        self._stop_push()
        if self._sock:
            self._sock.close()
            self._sock = None
        LOGGER.info("Shutdown complete")


###############################################################################
# ──────────────────────────── CLI convenience ────────────────────────────── #
###############################################################################

def _parse_cli(argv: List[str] | None = None) -> argparse.Namespace:  # noqa: D401
    ap = argparse.ArgumentParser(description="Minimal GB28181 test‑stream pusher")
    ap.add_argument("--server-ip", required=True, help="GB28181 platform SIP IP")
    ap.add_argument("--server-port", type=int, default=5060, help="SIP port [5060]")
    ap.add_argument("--server-id", required=True, help="Platform device ID (PLAT_ID)")
    ap.add_argument("--domain", help="Domain (default = first 10 digits of --server-id)")
    ap.add_argument("--agent-id", required=True, help="Our device ID")
    ap.add_argument("--agent-password", required=True, help="Password for Digest auth")
    ap.add_argument("--channel-id", required=True, help="Channel ID (camera) to advertise")
    ap.add_argument("--source", default="test", help="Media source URI (default: videotestsrc)")
    ap.add_argument("--udp", action="store_true", help="Use UDP for SIP signalling instead of TCP")
    ap.add_argument("--local-ip", help="Local IP to bind (auto‑detect if omitted)")
    ap.add_argument("--verbose", action="store_true", help="Dump full SIP packets")
    return ap.parse_args(argv)


def main(argv: List[str] | None = None) -> None:  # noqa: D401
    ns = _parse_cli(argv)
    pusher = GB28181Pusher(
        server_ip=ns.server_ip,
        server_port=ns.server_port,
        server_id=ns.server_id,
        domain=ns.domain,
        agent_id=ns.agent_id,
        agent_password=ns.agent_password,
        channel_id=ns.channel_id,
        source=ns.source,
        use_udp_signalling=ns.udp,
        local_ip=ns.local_ip,
        verbose=ns.verbose,
    )
    try:
        pusher.run_forever()
    except KeyboardInterrupt:
        LOGGER.info("Interrupted by user — exiting …")
    finally:
        pusher._shutdown()


if __name__ == "__main__":
    main()
