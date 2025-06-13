# sbgb28181 Pusher

[English](Readme_EN.md)

> **基于 Python + GStreamer 的轻量级 GB28181 设备示例**——自动 REGISTER、响应 INVITE，并使用 GStreamer 推送 **PS/H.264** 视频流。

本仓库提供一个简洁的 **GB28181** 参考实现，可将任意视频源模拟为摄像头侧设备并推流到 GB28181 媒体服务器。信令交互由 Python 脚本负责，媒体发送则依赖自制 `gb28181sink` GStreamer 插件。

---

## 🎯 主要特性

| 功能                  | 说明                                                          |
| ------------------- | ----------------------------------------------------------- |
| **TCP / UDP 信令**    | 默认使用 TCP，可通过 `--udp` 切换到 UDP                                |
| **TCP / UDP 媒体流**   | 支持 UDP 及 TCP *被动模式* 传输视频流                                   |
| **标准 PS 封装**        | 基于 `gb28181sink` 插件推送符合国标的 PS 流（96/PT 或按 SDP 协商）            |
| **命令行参数化**          | 平台 IP/端口、设备/平台 ID、密码等均可在启动时指定                               |
| **自动 REGISTER**     | 内置 Digest‑401 质询处理，支持多次重试                                   |
| **SDP / INVITE 解析** | 按 GB28181 规范优先选择 96/PS、98/H264 等 PayloadType                |
| **GStreamer 推流**    | 根据 SDP 动态拼装 `gst-launch-1.0` pipeline，支持 PS/H.264 及 TCP/UDP |
| **心跳与查询响应**         | 周期 *Keepalive*，并对 *Catalog* / *DeviceInfo* 查询作出响应           |
| **自动重连机制**          | 连接断开时自动重连，可配置重连间隔和最大重试次数                                  |
| **日志系统**            | `--verbose` 输出完整 SIP 报文，便于抓包与调试                             |

---

## 📦 依赖环境

* **Python ≥ 3.9**（已在 Ubuntu 22.04 验证）
* **GStreamer ≥ 1.18** 及自编译的 `gb28181sink` 插件

### 安装 GStreamer 及编译依赖
```bash
sudo apt update
sudo apt install -y gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good
sudo apt install -y meson ninja-build \
     libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
     libglib2.0-dev
```

### 编译 gb28181sink 插件
```bash
cd gst-gb28181sink
meson setup build
meson compile -C build
# 安装到系统插件目录(默认在/usr/local/lib/aarch64-linux-gnu/gstreamer-1.0)
sudo meson install -C build
# 如想放用户目录，可跳过 install 并设置：
# export GST_PLUGIN_PATH=$PWD/build
# 确认插件已注册
gst-inspect-1.0 gb28181sink
# 如果找不到则拷贝过去
# sudo cp build/libgstgb28181sink.so /usr/lib/aarch64-linux-gnu/gstreamer-1.0/
```

### 本地测试示例
```bash
# TCP被动模式
# 本地运行，监听9527端口
nc -l 9527 | hexdump -C | less
# 新开个窗口，运行
gst-launch-1.0 videotestsrc is-live=true ! video/x-raw,width=640,height=480,framerate=25/1 ! \
 x264enc key-int-max=50 tune=zerolatency bitrate=800 ! \
 h264parse ! mpegpsmux ! \
 gb28181sink protocol=tcp host=127.0.0.1 port=9527 pt=96 ssrc=0x01020304
# 监听的端口需要能收到数据
```


---

## 🚀 快速开始

```bash
python3 gb28181_pusher.py \
    --server-ip 192.168.1.100 --server-port 5060 \
    --server-id 11009000000000000000 --domain 1100900000 \
    --agent-id 300000000010000000000 --agent-password 000000 \
    --channel-id 340000000000000000000 \
    --source test \
    --verbose # 显示所有 SIP 包
# 可根据需要，在gst_cmd字段修改成需要的视频源
```

> 若平台使用 UDP 信令，在最后加上 `--udp`。

启动后脚本将：

1. 使用 SIP **REGISTER** 登录平台。
2. 每 60 秒发送一次 **Keepalive**。
3. 等待平台 **INVITE**，收到后自动 100 Trying → 200 OK 并解析 SDP。
4. 根据 SDP 用 GStreamer 向平台指定的 IP/端口推送PS视频流。
5. 处理 **BYE**、**MESSAGE**、**SUBSCRIBE** 并返回 200 OK。
6. **自动重连**：当连接断开时，自动尝试重新连接和注册。

---

## 🛠️ 主要命令行参数

| 参数                         | 默认                 | 说明                                |
| -------------------------- | ------------------ | --------------------------------- |
| `--server-ip`              | *必填*               | 平台 SIP IP                         |
| `--server-port`            | 5060               | 平台 SIP 端口                         |
| `--server-id`              | *必填*               | 平台国标编号（`PLAT_ID`）                 |
| `--domain`                 | `server-id` 前 10 位 | SIP 域                             |
| `--agent-id`               | *必填*               | 本设备国标编号                           |
| `--agent-password`         | *必填*               | REGISTER Digest 密码                |
| `--channel-id`             | *必填*               | 上报给平台的通道编号                        |
| `--source`                 | *test*             | 视频源                              |
| `--udp`                    | *关闭*               | 使用 **UDP** 而非默认 **TCP** 进行 SIP 交互 |
| `--local-ip`               | 自动探测               | 绑定本地网卡                            |
| `--verbose`                | *关闭*               | 输出调试日志及完整 SIP 报文                  |
| `--reconnect-interval`     | 5                  | 重连间隔时间（秒）                         |
| `--max-reconnect-attempts` | 0                  | 最大重连次数（0 = 无限重连）                  |
| `--connection-timeout`     | 10                 | 连接超时时间（秒）                         |

其中 `--source` 参数可指定视频源，支持多种格式：

| 示例                                                                    | 效果                    |
|-----------------------------------------------------------------------| --------------------- |
| `--source test`                                                       | 内置 `videotestsrc`（默认） |
| `--source rtsp://admin:admin@192.168.111.222/h264/ch1/main/av_stream` | 从 RTSP 摄像机拉流          |
| `--source udp://:5000`                                                | 监听组播 UDP 码流           |
| `--source file://sample.mp4`                                          | 播放本地文件并推流             |
| `--source v4l2:///dev/video0`                                         | 直接采集本地摄像头             |

---

## 📚 附加工具

* [`Tools/BuildGB28181Server.md`](Tools/BuildGB28181Server.md)：记录了如何搭建一个GB28181的媒体服务器，基于ZLMediaKit和wvp-GB28181-pro的组合。
* [`Tools/gb28181_proxy.py`](Tools/gb28181_proxy.py)：一个简单的GB28181转发代理，记录GB28181的信令交互过程，记录视频流的原始包，主要用于研究和调试，可配合Wireshark抓包使用。
> 让海康或者其他支持GB28181的设备向本机的5060端口注册，即可转发到xxx.xxx.xxx.xxx的5060端口，并查看整个交互过程。

```bash
python3 gb28181_proxy.py \
    --listen-host 0.0.0.0 \
    --listen-port 5060 \
    --server-host xxx.xxx.xxx.xxx \
    --server-port 5060
```

## 🧑‍💻 辅助编程

OpenAI o3 和 Gemini 2.5 Pro