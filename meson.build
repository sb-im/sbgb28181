project('gb28181sink', 'c', version : '1.0')

# GStreamer & GLib deps
gst_dep = dependency('gstreamer-1.0', version : '>=1.18')
gstbase_dep = dependency('gstreamer-base-1.0')
gio_dep = dependency('gio-2.0')

# Define PACKAGE / VERSION macros expected by GST_PLUGIN_DEFINE
add_project_arguments(
    '-DVERSION="' + meson.project_version() + '"',
    '-DPACKAGE="gb28181sink"',
    language : 'c')

srcs = ['gb28181sink.c']

shared_library('gstgb28181sink', srcs,
               dependencies : [gst_dep, gstbase_dep, gio_dep],
               install : true,
               install_dir : join_paths(get_option('libdir'), 'gstreamer-1.0'))
