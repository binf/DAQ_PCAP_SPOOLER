/*
** Based on Sourcefire External DAQ Module examples and some code from other DAQ Modules.
**
** Author: Eric Lauzon <beenph@gmail.com> 2012
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA,
** or look on the Interweb!
*/

#ifndef _DAQ_PCAP_SPOOLER_H
#define _DAQ_PCAP_SPOOLER_H


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Should we support other type of pcap out there ? */
#define TCPDUMP_MAGIC 0xa1b2c3d4

#define DAQ_PCAP_SPOOLER_VERSION 2

#define DAQ_PCAP_SPOOLER_CAPABILITIES  (DAQ_CAPA_UNPRIV_START|DAQ_CAPA_BPF|DAQ_CAPA_BREAKLOOP);

#define DEFAULT_PCAP_SPOOLER_BLOCK_MULTIPLE 128


#define DEFAULT_PCAP_SPOOLER_FILE_PREFIX "daemonlogger.pcap"
#define DEFAULT_PCAP_SPOOLER_SPOOL_DIRECTORY "/var/log/snort/log"
#define DEFAULT_PCAP_SPOOLER_ARCHIVE_DIRECTORY "/var/log/snort/archive"
#define DEFAULT_PCAP_SPOOLER_REFERENCE_FILE "/var/log/snort/PSRF"
#define DEFAULT_PCAP_SPOOLER_UPDATE_WINDOW 50


typedef struct _PcapReference
{
    char file_prefix[PATH_MAX];
    char spooler_directory[PATH_MAX];
    char archive_directory[PATH_MAX];
    u_int32_t timestamp;
    off_t last_read_offset;
    ssize_t saved_size;
} PcapReference;


typedef struct _pcap_spooler_context 
{
    
    /* Configuration Parameters */
    u_int8_t enable_archive;
    u_int8_t enable_debug;

    u_int32_t block_size_read;
    char *file_prefix;
    char *spooler_directory;
    char *archive_directory;
    char *pcap_reference_file;
    u_int32_t pcap_update_window;
    /* Configuration Parameters */
    
    /* Contextual information */
    DIR *spooler_dir;

    PcapReference pcap_reference;
    struct stat pcap_stat;
    
    char pcap_file_temp_name[PATH_MAX];
    char *read_buffer;
    u_int32_t read_buffer_size;
    
    u_int8_t bpf_recompile_filter;
    char *bpf_filter_backup; /* used if  */

    u_int32_t current_timestamp;    
    int packet_reference_fd;
    int pcap_fd;
    
    u_int8_t has_PR;
    u_int8_t has_PCAP;
    u_int8_t read_full;

    u_int32_t read_packet;

    /* Contextual information */
    
    
    /* Generic information */
    struct sfbpf_program bpf_filter;
    DAQ_Analysis_Func_t analysis_func;
    DAQ_Stats_t stats;
    DAQ_State state;
    
    char errbuf[DAQ_ERRBUF_SIZE];

    int snaplen;
    int data_link_type;
    /* Generic information */

} pcap_spooler_context;


/**
 **
 ** DAQ FUNCTIONS PROTOTYPES
 **
 **/
static int pcap_spooler_daq_initialize(const DAQ_Config_t * config, void **ctxt_ptr, char *errbuf, size_t len);
static int pcap_spooler_daq_set_filter(void *handle, const char *filter);
static int pcap_spooler_daq_get_stats(void *handle, DAQ_Stats_t * stats);
static void pcap_spooler_daq_reset_stats(void *handle);
static int pcap_spooler_daq_start(void *handle);
static int pcap_spooler_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback,DAQ_Meta_Func_t metaback, void *user);
static int pcap_spooler_daq_breakloop(void *handle);
static int pcap_spooler_daq_stop(void *handle);
static void pcap_spooler_daq_shutdown(void *handle);
static DAQ_State pcap_spooler_daq_check_status(void *handle);
static int pcap_spooler_daq_get_snaplen(void *handle);
static const char *pcap_spooler_daq_get_errbuf(void *handle);
static void pcap_spooler_daq_set_errbuf(void *handle, const char *string);
static uint32_t pcap_spooler_daq_get_capabilities(void *handle);
static int pcap_spooler_daq_get_datalink_type(void *handle);
/**
 **
 ** DAQ FUNCTIONS PROTOTYPES
 **
 **/



/**
 **
 ** PCAP SPOOLER FUNCTIONS PROTOTYPES
 **
 **/
static void pcap_spooler_debug_print(pcap_spooler_context *i_psctx,char *fmt,...);
static u_int32_t pcap_spooler_read_bulk(int fd,void *buffer, ssize_t read_size,ssize_t *r_read_size);
static u_int32_t pcap_spooler_write_pcap_reference(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_get_stat(int fd,struct stat *pr_stat);
static u_int32_t pcap_spooler_get_header(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_close_pcap(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_open_pcap(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_open_pcap_reference(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_create_pcap_reference(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_compare_pcap_reference(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_default(pcap_spooler_context *i_psctx);
static u_int32_t pcap_spooler_initialize(pcap_spooler_context *i_psctx);
static int pcap_spooler_parse_args(pcap_spooler_context *i_psctx,const DAQ_Config_t * config,void **ctxt_ptr);
static u_int32_t pcap_spooler_move_pcap(pcap_spooler_context *i_psctx);
static int pcap_spooler_directory_filter(const struct dirent *pcap_file_comp);
static u_int32_t pcap_spooler_monitor_directory(pcap_spooler_context *i_psctx);
static int pcap_spooler_daq_dummy_funct(void *,...);
/**
 **
 ** PCAP SPOOLER FUNCTIONS PROTOTYPES
 **
 **/

#endif /* _DAQ_PCAP_SPOOLER_H */
