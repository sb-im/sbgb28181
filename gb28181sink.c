#include <gst/gst.h>
#include <gst/base/gstbasesink.h>
#include <gio/gio.h>

GST_DEBUG_CATEGORY_STATIC (gb28181_sink_debug);
#define GST_CAT_DEFAULT gb28181_sink_debug

/* Tunables */
#define MAX_PAYLOAD 1400  /* RTP payload size */

typedef struct _Gb28181Sink {
    GstBaseSink parent;
    gchar *host;
    gint port;
    guint32 ssrc;
    guint8 pt;  /* RTP */
    GSocket *socket;
    GOutputStream *ostream;
    guint16 seq;
    guint32 ts_init;   /* starting RTP timestamp */
    GstClockTime ts_base;
} Gb28181Sink;

typedef struct _Gb28181SinkClass {
    GstBaseSinkClass parent_class;
} Gb28181SinkClass;

G_DEFINE_TYPE_WITH_CODE (Gb28181Sink, gb28181_sink, GST_TYPE_BASE_SINK,
                         GST_DEBUG_CATEGORY_INIT(gb28181_sink_debug, "gb28181sink", 0, "debug"));

/* ── properties ── */
enum {
    PROP_0, PROP_HOST, PROP_PORT, PROP_SSRC, PROP_PT
};
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 9000
#define DEFAULT_PT    96
#define DEFAULT_SSRC  0  /* 0 = auto(random) */

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
        case PROP_SSRC:
            s->ssrc = g_value_get_uint(v);
            break;
        case PROP_PT:
            s->pt = (guint8) g_value_get_uchar(v);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(o, id, p);
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
        case PROP_SSRC:
            g_value_set_uint(v, s->ssrc);
            break;
        case PROP_PT:
            g_value_set_uchar(v, s->pt);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(o, id, p);
    }
}

/* ── helper ── */
static inline guint32 ns_to_90k(guint64 ns) { return (guint32) gst_util_uint64_scale(ns, 90000, GST_SECOND); }

/* ── start/stop ── */
static gboolean sink_start(GstBaseSink *bs) {
    Gb28181Sink *s = (Gb28181Sink *) bs;
    GError *e = NULL;
    GSocketClient *c = g_socket_client_new();
    GSocketConnection *conn = g_socket_client_connect_to_host(c, s->host, s->port, NULL, &e);
    if (!conn) {
        GST_ELEMENT_ERROR(s, RESOURCE, OPEN_READ_WRITE, ("connect %s:%d %s", s->host, s->port, e ? e->message : ""),
                          NULL);
        g_clear_error(&e);
        g_object_unref(c);
        return FALSE;
    }
    s->ostream = g_io_stream_get_output_stream(G_IO_STREAM(conn));
    s->socket = g_object_ref(g_socket_connection_get_socket(conn));
    g_object_unref(c);
    s->seq = 0;
    if (s->ssrc == 0) s->ssrc = g_random_int();
    s->ts_init = g_random_int();  /* random initial RTP TS */
    s->ts_base = GST_CLOCK_TIME_NONE;
    GST_INFO_OBJECT(s, "TCP OK SSRC=0x%08x PT=%u", s->ssrc, s->pt);
    return TRUE;
}

static gboolean sink_stop(GstBaseSink *bs) {
    Gb28181Sink *s = (Gb28181Sink *) bs;
    if (s->ostream) {
        g_output_stream_close(s->ostream, NULL, NULL);
        s->ostream = NULL;
    }
    if (s->socket) {
        g_object_unref(s->socket);
        s->socket = NULL;
    }
    return TRUE;
}

/* ── render ── */
static GstFlowReturn sink_render(GstBaseSink *bs, GstBuffer *buf) {
    Gb28181Sink *s = (Gb28181Sink *) bs;
    if (!s->ostream)return GST_FLOW_ERROR;
    GstMapInfo m;
    if (!gst_buffer_map(buf, &m, GST_MAP_READ))return GST_FLOW_ERROR;
    guint32 rtp_ts;
    if (GST_BUFFER_PTS_IS_VALID(buf)) {
        if (G_UNLIKELY(s->ts_base == GST_CLOCK_TIME_NONE)) s->ts_base = GST_BUFFER_PTS(buf);
        rtp_ts = s->ts_init + ns_to_90k(GST_BUFFER_PTS(buf) - s->ts_base);
    } else rtp_ts = s->ts_init;

    guint offset = 0;
    while (offset < m.size) {
        guint chunk = MIN(MAX_PAYLOAD, m.size - offset);
        /* length */
        guint16 rfc_len = htons(chunk + 12);
        /* RTP header */
        guint8 h[12];
        gboolean last = (offset + chunk) == m.size;
        h[0] = 0x80;
        h[1] = (last ? 0x80 : 0x00) | s->pt;
        h[2] = s->seq >> 8;
        h[3] = s->seq & 0xFF;
        s->seq++;
        h[4] = rtp_ts >> 24;
        h[5] = rtp_ts >> 16;
        h[6] = rtp_ts >> 8;
        h[7] = rtp_ts;
        h[8] = s->ssrc >> 24;
        h[9] = s->ssrc >> 16;
        h[10] = s->ssrc >> 8;
        h[11] = s->ssrc;

        GError *e = NULL;
        if (!g_output_stream_write_all(s->ostream, &rfc_len, 2, NULL, NULL, &e) ||
            !g_output_stream_write_all(s->ostream, h, 12, NULL, NULL, &e) ||
            !g_output_stream_write_all(s->ostream, m.data + offset, chunk, NULL, NULL, &e)) {
            GST_ELEMENT_ERROR(s, RESOURCE, WRITE, ("socket %s", e ? e->message : ""), NULL);
            g_clear_error(&e);
            gst_buffer_unmap(buf, &m);
            return GST_FLOW_ERROR;
        }
        offset += chunk;
    }
    gst_buffer_unmap(buf, &m);
    return GST_FLOW_OK;
}

/* ── finalize ── */
static void sink_finalize(GObject *o) {
    Gb28181Sink *s = (Gb28181Sink *) o;
    g_free(s->host);
    G_OBJECT_CLASS(gb28181_sink_parent_class)->finalize(o);
}

/* ── class init ── */
static void gb28181_sink_class_init(Gb28181SinkClass *cls) {
    GObjectClass *g = G_OBJECT_CLASS(cls);
    g->set_property = set_prop;
    g->get_property = get_prop;
    g->finalize = sink_finalize;
    GstElementClass *e = GST_ELEMENT_CLASS(cls);
    GstBaseSinkClass *bs = GST_BASE_SINK_CLASS(cls);
    g_object_class_install_property(g, PROP_HOST, g_param_spec_string("host", "Host", "Destination", DEFAULT_HOST,
                                                                      G_PARAM_READWRITE));
    g_object_class_install_property(g, PROP_PORT, g_param_spec_int("port", "Port", "Dest port", 1, 65535, DEFAULT_PORT,
                                                                   G_PARAM_READWRITE));
    g_object_class_install_property(g, PROP_SSRC,
                                    g_param_spec_uint("ssrc", "SSRC", "RTP SSRC (0=random)", 0, G_MAXUINT32,
                                                      DEFAULT_SSRC, G_PARAM_READWRITE));
    g_object_class_install_property(g, PROP_PT, g_param_spec_uchar("pt", "PayloadType", "RTP PT", 0, 127, DEFAULT_PT,
                                                                   G_PARAM_READWRITE));
    gst_element_class_set_static_metadata(e, "GB28181 RTP/PS Sink", "Sink/Network", "Send MPEG-PS in RTP/TCP",
                                          "Leo@sb");
    GstCaps *caps = gst_caps_from_string("video/mpeg, systemstream=(boolean)true, mpegversion=(int)2");
    gst_element_class_add_pad_template(e, gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, caps));
    gst_caps_unref(caps);
    bs->start = sink_start;
    bs->stop = sink_stop;
    bs->render = sink_render;
}

static void gb28181_sink_init(Gb28181Sink *s) {
    s->host = g_strdup(DEFAULT_HOST);
    s->port = DEFAULT_PORT;
    s->pt = DEFAULT_PT;
    s->ssrc = DEFAULT_SSRC;
}

/* plugin entry */
static gboolean plugin_init(GstPlugin *p) {
    return gst_element_register(p, "gb28181sink", GST_RANK_NONE, gb28181_sink_get_type());
}

GST_PLUGIN_DEFINE(GST_VERSION_MAJOR, GST_VERSION_MINOR, gb28181sink, "GB28181 RTP/PS Sink", plugin_init, "1.0", "LGPL",
                  "gb28181sink", "https://sb.im")
