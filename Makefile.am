AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = daq_pcap_spooler.la
daq_pcap_spooler_la_SOURCES = daq_pcap_spooler.c
daq_pcap_spooler_la_CFLAGS = -DBUILDING_SO
daq_pcap_spooler_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
