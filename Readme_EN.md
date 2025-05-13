# sbgb28181 Pusher

[中文版](Readme.md)

> **A minimal GB28181 device written in Python + GStreamer** — performs REGISTER, answers INVITE and pushes **PS / H.264** test video to a GB28181 media server.

This repository contains a lean **GB28181** reference implementation that turns *any* video source into a mock camera and streams it to a GB28181‑compatible server. SIP signalling is handled by a Python script, while media delivery relies on a custom `gb28181sink` *GStreamer* plugin.

---

## 🎯 Features

| Feature                        | Description                                                       |
| ------------------------------ | ----------------------------------------------------------------- |
| **TCP / UDP signalling**       | Uses **TCP** by default, switch to UDP with `--udp`               |
| **TCP / UDP media**            | Supports UDP or *passive* TCP RTP/PS streaming                    |
| **Stand‑alone PS muxer**       | Streams standard **Program Stream** (PT 96) via `gb28181sink`     |
| **Fully CLI‑configurable**     | Platform IP, ports, IDs, password … all via parameters            |
| **Automatic REGISTER**         | Built‑in Digest‑401 handling with retry logic                     |
| **SDP / INVITE parsing**       | Follows GB28181 rules (prefers 96/PS, 98/H264)                    |
| **Dynamic GStreamer pipeline** | Builds a `gst-launch-1.0` pipeline on‑the‑fly (PS/H.264, TCP/UDP) |
| **Keepalive & query replies**  | Periodic *Keepalive*, answers *Catalog* / *DeviceInfo* queries    |
| **Verbose logging**            | `--verbose` dumps full SIP packets for easy debugging             |

---

## 📦 Requirements

* **Python ≥ 3.9**
* **GStreamer ≥ 1.18**

### Install GStreamer & build deps

```bash
sudo apt install -y gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good
sudo apt install -y meson ninja-build \
     libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
     libglib2.0-dev
```

### Build the `gb28181sink` plugin

```bash
cd gst-gb28181sink
meson setup build
meson compile -C build
sudo meson install -C build   # installs to /usr/local/lib/<arch>/gstreamer-1.0

# If you prefer a user‑local install, skip *install* and set:
# export GST_PLUGIN_PATH=$PWD/build

# Verify the plugin is available
gst-inspect-1.0 gb28181sink
```

### Local loopback test

```bash
# 1. Terminal A: listen on TCP port 9527
nc -l 9527 | hexdump -C | less

# 2. Terminal B: push a test card via GStreamer
gst-launch-1.0 videotestsrc is-live=true ! video/x-raw,width=640,height=480,framerate=25/1 \
  ! x264enc key-int-max=50 tune=zerolatency bitrate=800 \
  ! h264parse ! mpegpsmux \
  ! gb28181sink protocol=tcp host=127.0.0.1 port=9527 pt=96 ssrc=0x01020304
```

---

## 🚀 Quick Start

```bash
python3 gb28181_pusher.py \
  --server-ip 192.168.1.100 --server-port 5060 \
  --server-id 11009000000000000000 --domain 1100900000 \
  --agent-id 300000000010000000000 --agent-password 000000 \
  --channel-id 340000000000000000000 \
  --source test \
  --verbose           # dump SIP packets
```

> Add `--udp` if your platform expects **UDP** signalling.

What happens next:

1. The script **REGISTERs** to the platform.
2. Sends a *Keepalive* every 60 s.
3. Waits for an **INVITE**, replies `100 Trying` → `200 OK` and parses SDP.
4. Builds an appropriate GStreamer pipeline to push PS / H.264 to the announced IP/port.
5. Handles `BYE`, `MESSAGE`, `SUBSCRIBE` and returns `200 OK` accordingly.

---

## 🛠️ CLI Options

| Option             | Default                        | Description                                        |
| ------------------ | ------------------------------ |----------------------------------------------------|
| `--server-ip`      | *required*                     | Platform SIP address                               |
| `--server-port`    | `5060`                         | Platform SIP port                                  |
| `--server-id`      | *required*                     | Platform GB ID (`PLAT_ID`)                         |
| `--domain`         | first 10 digits of `server-id` | SIP domain                                         |
| `--agent-id`       | *required*                     | Our device GB ID                                   |
| `--agent-password` | *required*                     | Digest password                                    |
| `--channel-id`     | *required*                     | Channel (camera) ID to advertise                   |
| `--source`         | *test*                         | Video source                                       |
| `--udp`            | *false*                        | Use **UDP** instead of the default **TCP** for SIP |
| `--local-ip`       | auto‑detect                    | Local bind address                                 |
| `--verbose`        | *false*                        | Dump debug logs & full SIP packets                 |

The `--source` parameter can specify the video source:

| Example                                                                 | Effect                                       |
|-----------------------------------------------------------------------|----------------------------------------------|
| `--source test`                                                       | Built-in `videotestsrc` (default)            |
| `--source rtsp://admin:admin@192.168.111.222/h264/ch1/main/av_stream` | Pulls stream from an RTSP camera             |
| `--source udp://:5000`                                                | Listens for a multicast UDP stream           |
| `--source file://sample.mp4`                                          | Plays a local file and streams it            |
| `--source v4l2:///dev/video0`                                         | Directly captures from a local camera        |

---

## 📚 Tools

* `Tools/BuildGB28181Server.md` — step‑by‑step guide to spin up a server with **ZLMediaKit + wvp‑GB28181‑pro**
* `Tools/gb28181_proxy.py` — simple GB28181 proxy that logs signalling & raw media packets; handy for Wireshark analysis

---

## 🧑‍💻 Copilot

OpenAI o3 and Gemini 2.5 Pro