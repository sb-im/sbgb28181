#include <gst/gst.h>
#include <gst/base/gstbasesink.h>
#include <gio/gio.h>
#include <string.h>

GST_DEBUG_CATEGORY_STATIC (gb28181_sink_debug);
#define GST_CAT_DEFAULT gb28181_sink_debug

#define MAX_PAYLOAD 1400          /* max PS bytes in one RTP packet */

typedef enum {
    GB_PROTO_TCP, GB_PROTO_UDP
} GbProto;

typedef struct _Gb28181Sink {
    GstBaseSink parent;
    gchar *host;
    gint port;
    GbProto proto;
    guint32 ssrc;
    guint8 pt;
    GSocket *sock;          /* both */
    GOutputStream *ostream; /* only tcp */
    guint16 seq;
    guint32 ts_init;
    GstClockTime ts_base;
} Gb28181Sink;

typedef struct _Gb28181SinkClass {
    GstBaseSinkClass parent_class;
} Gb28181SinkClass;

G_DEFINE_TYPE_WITH_CODE (Gb28181Sink, gb28181_sink, GST_TYPE_BASE_SINK,
                         GST_DEBUG_CATEGORY_INIT(gb28181_sink_debug, "gb28181sink", 0, "debug"));

/* ── props ── */
enum {
    PROP_0, PROP_HOST, PROP_PORT, PROP_PROTOCOL, PROP_SSRC, PROP_PT
};
#define DEF_HOST "127.0.0.1"
#define DEF_PORT 9000
#define DEF_PT   96

static GbProto proto_from_str(const gchar *s) {
    return g_ascii_strcasecmp(s, "udp") == 0 ? GB_PROTO_UDP : GB_PROTO_TCP;
}

static const gchar *proto_to_str(GbProto p) { return p == GB_PROTO_UDP ? "udp" : "tcp"; }

static void set_prop(GObject *o, guint id, const GValue *v, GParamSpec *p) {
    Gb28181Sink *s = (Gb28181Sink *) o;
    switch (id) {
        case PROP_HOST:
            g_free(s->host);
            s->host = g_value_dup_string(v);
            break;
        case PROP_PORT:
            s->port = g_value_get_int(v);
            break;
        case PROP_PROTOCOL:
            s->proto = proto_from_str(g_value_get_string(v));
            break;
        case PROP_SSRC:
            s->ssrc = g_value_get_uint(v);
            break;
        case PROP_PT:
            s->pt = (guint8) g_value_get_uchar(v);
            break;
    }
}

static void get_prop(GObject *o, guint id, GValue *v, GParamSpec *p) {
    Gb28181Sink *s = (Gb28181Sink *) o;
    switch (id) {
        case PROP_HOST:
            g_value_set_string(v, s->host);
            break;
        case PROP_PORT:
            g_value_set_int(v, s->port);
            break;
        case PROP_PROTOCOL:
            g_value_set_string(v, proto_to_str(s->proto));
            break;
        case PROP_SSRC:
            g_value_set_uint(v, s->ssrc);
            break;
        case PROP_PT:
            g_value_set_uchar(v, s->pt);
            break;
    }
}

static inline guint32 ns90(guint64 ns) { return (guint32) gst_util_uint64_scale(ns, 90000, GST_SECOND); }

/* ── start/stop ── */
static gboolean sink_start(GstBaseSink *bs) {
    Gb28181Sink *s = (Gb28181Sink *) bs;
    GError *e = NULL;
    if (s->proto == GB_PROTO_TCP) {
        GSocketClient *c = g_socket_client_new();
        GSocketConnection *conn = g_socket_client_connect_to_host(c, s->host, s->port, NULL, &e);
        if (!conn) {
            GST_ELEMENT_ERROR(s, RESOURCE, OPEN_READ_WRITE, ("TCP connect fail %s", e ? e->message : ""), NULL);
            g_clear_error(&e);
            g_object_unref(c);
            return FALSE;
        }
        s->ostream = g_io_stream_get_output_stream(G_IO_STREAM(conn));
        s->sock = g_object_ref(g_socket_connection_get_socket(conn));
        g_object_unref(c);
    } else {
        s->sock = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM, G_SOCKET_PROTOCOL_UDP, &e);
        if (!s->sock) {
            GST_ELEMENT_ERROR(s, RESOURCE, OPEN_READ_WRITE, ("UDP socket %s", e ? e->message : ""), NULL);
            g_clear_error(&e);
            return FALSE;
        }
        GInetAddress *addr = g_inet_address_new_from_string(s->host);
        GSocketAddress *sa = g_inet_socket_address_new(addr, s->port);
        g_object_unref(addr);
        if (!g_socket_connect(s->sock, sa, NULL, &e)) {
            GST_ELEMENT_ERROR(s, RESOURCE, OPEN_READ_WRITE, ("UDP connect %s", e ? e->message : ""), NULL);
            g_clear_error(&e);
            g_object_unref(sa);
            return FALSE;
        }
        g_object_unref(sa);
    }
    if (s->ssrc == 0) s->ssrc = g_random_int();
    s->seq = 0;
    s->ts_init = g_random_int();
    s->ts_base = GST_CLOCK_TIME_NONE;
    GST_INFO_OBJECT(s, "started %s %s:%d", proto_to_str(s->proto), s->host, s->port);
    return TRUE;
}

static gboolean sink_stop(GstBaseSink *bs) {
    Gb28181Sink *s = (Gb28181Sink *) bs;
    if (s->ostream) {
        g_output_stream_close(s->ostream, NULL, NULL);
        s->ostream = NULL;
    }
    if (s->sock) {
        g_object_unref(s->sock);
        s->sock = NULL;
    }
    return TRUE;
}

/* ── send helpers ── */
static gboolean tcp_write(Gb28181Sink *s, const guint8 *buf, gsize len) {
    gsize w = 0;
    return g_output_stream_write_all(s->ostream, buf, len, &w, NULL, NULL);
}

static gboolean udp_send(Gb28181Sink *s, const guint8 *buf, gsize len) {
    return g_socket_send(s->sock, (const gchar *) buf, len, NULL, NULL) == (gssize) len;
}

/* ── render ── */
static GstFlowReturn sink_render(GstBaseSink *bs, GstBuffer *b) {
    Gb28181Sink *s = (Gb28181Sink *) bs;
    if (!s->sock)return GST_FLOW_ERROR;
    GstMapInfo m;
    if (!gst_buffer_map(b, &m, GST_MAP_READ))return GST_FLOW_ERROR;
    guint32 ts;
    if (GST_BUFFER_PTS_IS_VALID(b)) {
        if (G_UNLIKELY(s->ts_base == GST_CLOCK_TIME_NONE))s->ts_base = GST_BUFFER_PTS(b);
        ts = s->ts_init + ns90(GST_BUFFER_PTS(b) - s->ts_base);
    }
    else ts = s->ts_init;
    guint off = 0;
    while (off < m.size) {
        guint chunk = MIN(MAX_PAYLOAD, m.size - off);
        gboolean last = (off + chunk) == m.size;
        guint8 rtp[12];
        rtp[0] = 0x80;
        rtp[1] = (last ? 0x80 : 0x00) | s->pt;
        rtp[2] = s->seq >> 8;
        rtp[3] = s->seq & 0xFF;
        s->seq++;
        rtp[4] = ts >> 24;
        rtp[5] = ts >> 16;
        rtp[6] = ts >> 8;
        rtp[7] = ts;
        rtp[8] = s->ssrc >> 24;
        rtp[9] = s->ssrc >> 16;
        rtp[10] = s->ssrc >> 8;
        rtp[11] = s->ssrc;
        if (s->proto == GB_PROTO_TCP) {
            guint16 len = htons(chunk + 12);
            if (!tcp_write(s, (guint8 *) &len, 2) || !tcp_write(s, rtp, 12) || !tcp_write(s, m.data + off, chunk)) {
                gst_buffer_unmap(b, &m);
                return GST_FLOW_ERROR;
            }
        }
        else { /* UDP one-shot */
            guint total = 12 + chunk;
            guint8 *pkt = g_malloc(total);
            memcpy(pkt, rtp, 12);
            memcpy(pkt + 12, m.data + off, chunk);
            if (!udp_send(s, pkt, total)) {
                g_free(pkt);
                gst_buffer_unmap(b, &m);
                return GST_FLOW_ERROR;
            }
            g_free(pkt);
        }
        off += chunk;
    }
    gst_buffer_unmap(b, &m);
    return GST_FLOW_OK;
}

/* ── finalize ── */
static void sink_finalize(GObject *o) {
    Gb28181Sink *s = (Gb28181Sink *) o;
    g_free(s->host);
    G_OBJECT_CLASS(gb28181_sink_parent_class)->finalize(o);
}

/* ── class/init ── */
static void gb28181_sink_class_init(Gb28181SinkClass *cls) {
    GObjectClass *g = G_OBJECT_CLASS(cls);
    g->set_property = set_prop;
    g->get_property = get_prop;
    g->finalize = sink_finalize;
    GstElementClass *e = GST_ELEMENT_CLASS(cls);
    GstBaseSinkClass *bs = GST_BASE_SINK_CLASS(cls);
    g_object_class_install_property(g, PROP_HOST,
                                    g_param_spec_string("host", "Host", "Dest", DEF_HOST, G_PARAM_READWRITE));
    g_object_class_install_property(g, PROP_PORT, g_param_spec_int("port", "Port", "Dest port", 1, 65535, DEF_PORT,
                                                                   G_PARAM_READWRITE));
    g_object_class_install_property(g, PROP_PROTOCOL,
                                    g_param_spec_string("protocol", "Protocol", "tcp|udp", "tcp", G_PARAM_READWRITE));
    g_object_class_install_property(g, PROP_SSRC, g_param_spec_uint("ssrc", "SSRC", "0=random", 0, G_MAXUINT32, 0,
                                                                    G_PARAM_READWRITE));
    g_object_class_install_property(g, PROP_PT, g_param_spec_uchar("pt", "PayloadType", "RTP PT", 0, 127, DEF_PT,
                                                                   G_PARAM_READWRITE));
    gst_element_class_set_static_metadata(e, "GB28181 RTP/PS Sink", "Sink/Network", "Send MPEG-PS in RTP over TCP/UDP",
                                          "Leo@sb");
    GstCaps *c = gst_caps_from_string("video/mpeg, systemstream=(boolean)true, mpegversion=(int)2");
    gst_element_class_add_pad_template(e, gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, c));
    gst_caps_unref(c);
    bs->start = sink_start;
    bs->stop = sink_stop;
    bs->render = sink_render;
}

static void gb28181_sink_init(Gb28181Sink *s) {
    s->host = g_strdup(DEF_HOST);
    s->port = DEF_PORT;
    s->proto = GB_PROTO_TCP;
    s->pt = DEF_PT;
    s->ssrc = 0;
}

static gboolean plugin_init(GstPlugin *p) {
    return gst_element_register(p, "gb28181sink", GST_RANK_NONE, gb28181_sink_get_type());
}

GST_PLUGIN_DEFINE(GST_VERSION_MAJOR, GST_VERSION_MINOR, gb28181sink, "GB28181 RTP/PS Sink", plugin_init, "1.1", "LGPL",
                  "gb28181sink", "https://sb.im")