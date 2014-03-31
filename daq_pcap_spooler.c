/*
** Based on Sourcefire External DAQ Module examples, and some code from other DAQ Modules.
**
** Author: Eric Lauzon <beenph@gmail.com> 2012
**
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>



/* SF Includes */
#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>
/* SF Includes */
#include <errno.h>
extern int errno;

#include "daq_pcap_spooler.h"

//strtoull
#if  _POSIX_C_SOURCE <= 200112L
#define _POSIX_C_SOURCE  200112L
#endif 

#ifndef _BSD_SOURCE
#define _BSD_SOURCE 1
#endif
//

static char *pcap_file_prefix = NULL;
static int dir_filter_op_mode = 0;

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
    const DAQ_Module_t pcap_spooler_daq_module_data =
#endif
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_PCAP_SPOOLER_VERSION,
    .name = "pcap_spooler",
    
    /* Lie to snort so people are not confused when they try to use us ... we are the pigmogner */
    .type = DAQ_TYPE_FILE_CAPABLE|DAQ_TYPE_INTF_CAPABLE,
    .initialize = pcap_spooler_daq_initialize,
    .set_filter = pcap_spooler_daq_set_filter,
    .start = pcap_spooler_daq_start,
    .acquire = pcap_spooler_daq_acquire,
    .breakloop = pcap_spooler_daq_breakloop,
    .stop = pcap_spooler_daq_stop,
    .shutdown = pcap_spooler_daq_shutdown,
    .check_status = pcap_spooler_daq_check_status,
    .get_stats = pcap_spooler_daq_get_stats,
    .reset_stats = pcap_spooler_daq_reset_stats,
    .get_snaplen = pcap_spooler_daq_get_snaplen,
    .get_datalink_type = pcap_spooler_daq_get_datalink_type,
    .get_capabilities = pcap_spooler_daq_get_capabilities,
    .get_errbuf = pcap_spooler_daq_get_errbuf,
    .set_errbuf = pcap_spooler_daq_set_errbuf,
    
#ifdef BUILDING_SO
    .inject = (int (*)())pcap_spooler_daq_dummy_funct,
    .get_device_index = (int (*)())pcap_spooler_daq_dummy_funct,
#else
    /* Unsupported */
    .inject = NULL,           
    .get_device_index = NULL,  
    /* Unsupported */
#endif /* BUILDING_SO */
};



/**
 **
 ** PCAP SPOOLER FUNCTIONS
 **
 **/
static void pcap_spooler_debug_print(pcap_spooler_context *i_psctx,char *fmt,...)
{
    va_list ap;
    
    if((i_psctx == NULL) ||
       (fmt == NULL))
    {
	return;
    }
    
    if(i_psctx->enable_debug)
    {
	printf("===============================================\n"
               "[DAQ] <++> [%s] Debug Message \n"
	       "===============================================\n",
#ifdef BUILDING_SO
               DAQ_MODULE_DATA.name
#else
               pcap_spooler_daq_module_data.name
#endif
	    );
	
	va_start(ap, fmt);
	vprintf(fmt,ap);
	va_end(ap);
	
	printf("===============================================\n");

    }
    
    return;
}

static u_int32_t pcap_spooler_read_bulk(int fd,void *buffer, ssize_t read_size,ssize_t *r_read_size)
{
    if( (buffer == NULL) ||
	(r_read_size == NULL) ||
	(fd <= 0) || 
	(read_size <= 0))
    {
	return 1;
    }
    
    if( (*r_read_size=read(fd,buffer,read_size)) <= 0)
    {
	return 1;
    }
    
    return 0;
}

static u_int32_t pcap_spooler_write_pcap_reference(pcap_spooler_context *i_psctx)
{
    if( (i_psctx == NULL) ||
	(i_psctx->packet_reference_fd < 0))
    {
	return 1;
    }
    
    /* rewind the fd */
    if( lseek(i_psctx->packet_reference_fd,0,SEEK_SET) < 0)
    {
	return 1;
    }
    
    if( write(i_psctx->packet_reference_fd,&i_psctx->pcap_reference,sizeof(PcapReference)) != sizeof(PcapReference))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError writing to [%s]\n",
				 i_psctx->pcap_reference_file);
	return 1;
    }

    pcap_spooler_debug_print(i_psctx,(char *)
			     "\tWriting information to [%s] \n"
			     "\t--------------\n"
			     "\tPSRF Spooler Directory  -> [%s] \n"
			     "\tPSRF Archive Direcotory -> [%s] \n"
			     "\tPSRF File Prefix -> [%s] \n"
			     "\tPSRF timestamp -> [%u] \n"
#ifdef LARGEFILE_SUPPORT
			     "\tPSRF last read offset -> [%llu] \n"
#else
			     "\tPSRF last read offset -> [%u] \n"
#endif
			     "\tPSRF saved size -> [%u] \n"
			     "\tPSRF operation mode -> [%d] \n"
			     "\t--------------\n\n",
			     i_psctx->pcap_reference_file,
			     i_psctx->pcap_reference.spooler_directory,
			     i_psctx->pcap_reference.archive_directory,
			     i_psctx->pcap_reference.file_prefix,
			     i_psctx->pcap_reference.timestamp,
#ifdef LARGEFILE_SUPPORT
			     (u_int64_t)i_psctx->pcap_reference.last_read_offset,
#else
			     (u_int32_t)i_psctx->pcap_reference.last_read_offset,
#endif
			     (u_int32_t)i_psctx->pcap_reference.saved_size,
			     i_psctx->pcap_reference.operation_mode);
    
    return 0;
}

static u_int32_t pcap_spooler_get_stat(int fd,struct stat *pr_stat)
{
    if( (pr_stat == NULL) ||
	(fd < 0)) 
    {
	return 1;
    }
    
    if( fstat(fd,pr_stat) < 0)
    {
	return 1;
    }
    
    return 0;
}


static u_int32_t pcap_spooler_get_header(pcap_spooler_context *i_psctx)
{
    struct pcap_file_header pfh;
    
    ssize_t read_size = 0;
    
    if( (i_psctx == NULL) ||
	(i_psctx->pcap_fd < 0))
    {
	return 1;
    }
    
    memset(&pfh,'\0',sizeof(struct pcap_file_header));
    
    i_psctx->pcap_stat.st_size = 0;
    
    while(i_psctx->pcap_stat.st_size < (ssize_t)sizeof(struct pcap_file_header))
    {
	if( pcap_spooler_get_stat(i_psctx->pcap_fd,&i_psctx->pcap_stat))
	{
	    pcap_spooler_debug_print(i_psctx,(char *)
				     "\tError calling fstat on [%s]\n",
				     i_psctx->pcap_file_temp_name);
	    return 1;
	}
	
        pcap_spooler_debug_print(i_psctx,(char *)
				 "\tNo data has been written to [%s], waiting for pcap_file_header ...\n",
				 i_psctx->pcap_file_temp_name);
	usleep(200);
    }

    if(pcap_spooler_read_bulk(i_psctx->pcap_fd,&pfh,sizeof(struct pcap_file_header),&read_size))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError reading from [%s]\n",
				 i_psctx->pcap_file_temp_name);
	return 1;
    }
    
    if( (read_size < (ssize_t)(sizeof(struct pcap_file_header))) ||
	(pfh.magic != TCPDUMP_MAGIC))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tInvalid PCAP header for file [%s]\n",
				 i_psctx->pcap_file_temp_name);
	return 1;
    }
    
    i_psctx->snaplen = pfh.snaplen;
    i_psctx->data_link_type = pfh.linktype;
    
    
    return 0;
}

static u_int32_t pcap_spooler_close_pcap(pcap_spooler_context *i_psctx)
{
    if(i_psctx == NULL)
    {
	return 1;
    }
    
    if(i_psctx->pcap_fd)
    {
	close(i_psctx->pcap_fd);
    }
    
    i_psctx->pcap_fd=-1;
    
    i_psctx->has_PCAP = 0;
    
    return 0;
}

static u_int32_t pcap_spooler_open_pcap(pcap_spooler_context *i_psctx)
{

    /* YAF */
    char yaf_timestamp_str[15] = {0};
    char yaf_serial_str[20] = {0}; /* the serial size has grown in version 2.5 should be fine for a while..*/


    if(i_psctx == NULL)
    {
	return 1;
    }
    
    memset(i_psctx->pcap_file_temp_name,'\0',PATH_MAX);
    
    switch(i_psctx->operation_mode)
    {	
    case OPERATION_MODE_YAF:
	
	if( (pcap_spooler_yaf_utc_to_timestamp((time_t)i_psctx->pcap_reference.timestamp,yaf_timestamp_str)))
	{
	    return 1;
	}
	
	snprintf(yaf_serial_str,20,"%.llu",i_psctx->pcap_reference.serial);
	
	snprintf(i_psctx->pcap_file_temp_name,PATH_MAX,"%s/%s%c%s%c%s.pcap",
		 i_psctx->pcap_reference.spooler_directory,
		 i_psctx->pcap_reference.file_prefix,
		 i_psctx->pcap_reference.yaf_prefix_separator,
		 yaf_timestamp_str,
		 i_psctx->pcap_reference.yaf_separator,
		 yaf_serial_str);
	break;
	
    default:
	snprintf(i_psctx->pcap_file_temp_name,PATH_MAX,"%s/%s.%u",
		 i_psctx->pcap_reference.spooler_directory,
		 i_psctx->pcap_reference.file_prefix,
		 i_psctx->pcap_reference.timestamp);
	break;
    }
    
    pcap_spooler_debug_print(i_psctx,(char *)
			     "\tOpening [%s] \n",
			     i_psctx->pcap_file_temp_name);
    
    if( (i_psctx->pcap_fd = open(i_psctx->pcap_file_temp_name,O_RDONLY)) <=0)
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError opening file [%s]\n",
				 i_psctx->pcap_file_temp_name,
				 strerror(errno));
	return 1;
    }
    
    /* Make sure the file has some data,force the kernel. */
    if( fsync(i_psctx->pcap_fd))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError calling fsync() on [%s]\n",
				 i_psctx->pcap_file_temp_name);
	return 1;
    }
    
    if( pcap_spooler_get_stat(i_psctx->pcap_fd,&i_psctx->pcap_stat))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError calling fstat on [%s]\n",
				 i_psctx->pcap_file_temp_name);
	return 1;
    }
    
    /*Technically we do no read cross block device ..unless you have a wierd setup and you will know
      then how to change this behavior */
    if(i_psctx->read_buffer == NULL)
    {
	if( (i_psctx->read_buffer=calloc(i_psctx->pcap_stat.st_blksize,i_psctx->block_size_read)) == NULL)
	{
	    pcap_spooler_debug_print(i_psctx,(char *)
                                     "\tError reading from [%s]\n",
                                     i_psctx->pcap_file_temp_name);
	    return 1;
	}
	
	i_psctx->read_buffer_size = i_psctx->pcap_stat.st_blksize * i_psctx->block_size_read;
    }
    else
    {
	memset(i_psctx->read_buffer,'\0',i_psctx->read_buffer_size);
    }
    
    /* Shouldn't be needed but just in case */
    if(lseek(i_psctx->pcap_fd,0,SEEK_SET) != 0)
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError calling lseek() on  [%s]\n",
				 i_psctx->pcap_file_temp_name);
	return 1;
    }
    
    if( pcap_spooler_get_header(i_psctx))
    {
	return 1;
    }
    
    if(i_psctx->bpf_recompile_filter)
    {
	if( pcap_spooler_daq_set_filter((void *)i_psctx,i_psctx->bpf_filter_backup))
	{
	    return 1;
	}
    }
    
    i_psctx->has_PCAP = 1;
    
    return 0;
}



static u_int32_t pcap_spooler_open_pcap_reference(pcap_spooler_context *i_psctx)
{
    ssize_t read_len = 0;
    
    if(i_psctx == NULL)
    {
	return 1;
    }
    
    if( ( i_psctx->packet_reference_fd  = open(i_psctx->pcap_reference_file,O_RDWR)) < 0)
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError opening [%s]\n",
				 i_psctx->pcap_reference_file);
	return 1;
    }
    
    if( (pcap_spooler_read_bulk(i_psctx->packet_reference_fd,&i_psctx->pcap_reference,sizeof(PcapReference),&read_len)))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError reading [%s]\n",
				 i_psctx->pcap_reference_file);
	i_psctx->packet_reference_fd = -1;
	return 1;
    }
    
    
    if( (read_len < (ssize_t)sizeof(PcapReference)) ||
	(read_len > (ssize_t)sizeof(PcapReference)))
    {
	close(i_psctx->packet_reference_fd);
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tError reading [%s], invalid read size [%u] should be [%u]\n",
				 i_psctx->pcap_reference_file,
				 read_len,
				 sizeof(PcapReference));
	i_psctx->packet_reference_fd = -1;
	return 1;
    }

    pcap_file_prefix = i_psctx->pcap_reference.file_prefix;

    return 0;
}

static u_int32_t pcap_spooler_create_pcap_reference(pcap_spooler_context *i_psctx)
{
    if( (i_psctx == NULL) ||
	(i_psctx->packet_reference_fd > 0))
    {
	return 1;
    }
    
    if( (i_psctx->packet_reference_fd = open(i_psctx->pcap_reference_file,O_CREAT|O_RDWR,S_IRUSR|S_IWUSR)) < 0)
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tUnable to create [%s]\n",
				 i_psctx->pcap_reference_file);
        return 1;
    }
    
    /* Initialize PR */
    memset(&i_psctx->pcap_reference,'\0',sizeof(PcapReference));
    
    memcpy(i_psctx->pcap_reference.file_prefix,i_psctx->file_prefix,PATH_MAX);
    pcap_file_prefix = i_psctx->pcap_reference.file_prefix;
    
    memcpy(i_psctx->pcap_reference.spooler_directory,i_psctx->spooler_directory,PATH_MAX);
    memcpy(i_psctx->pcap_reference.archive_directory,i_psctx->archive_directory,PATH_MAX);
    
    i_psctx->pcap_reference.operation_mode = i_psctx->operation_mode;
    
    if(i_psctx->operation_mode == OPERATION_MODE_YAF)
    {
	i_psctx->pcap_reference.yaf_separator = i_psctx->yaf_separator;
	i_psctx->pcap_reference.yaf_prefix_separator = i_psctx->yaf_prefix_separator;
    }


    if( (pcap_spooler_write_pcap_reference(i_psctx)))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
                                 "\tUnable to write [%s]\n",
                                 i_psctx->pcap_reference_file);
	return 1;
    }

    return 0;
}


static u_int32_t pcap_spooler_compare_pcap_reference(pcap_spooler_context *i_psctx)
{
    if( (i_psctx == NULL) ||
	(i_psctx->packet_reference_fd < 0) )
    {
	return 1;
    }
    
    if( (strncmp(i_psctx->pcap_reference.file_prefix,i_psctx->file_prefix,strlen(i_psctx->pcap_reference.file_prefix)) != 0 ) ||
	(strncmp(i_psctx->pcap_reference.spooler_directory,i_psctx->spooler_directory,strlen(i_psctx->pcap_reference.spooler_directory)) !=0 ) ||
	(strncmp(i_psctx->pcap_reference.archive_directory,i_psctx->archive_directory,strlen(i_psctx->pcap_reference.archive_directory)) !=0 ) ||
	(i_psctx->pcap_reference.operation_mode != i_psctx->operation_mode) ||
	(i_psctx->pcap_reference.yaf_separator != i_psctx->yaf_separator) ||
	(i_psctx->pcap_reference.yaf_prefix_separator != i_psctx->yaf_prefix_separator))
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tERROR: [information from pcap spooler reference file [%s] does not match the DAQ variables] \n"
				 "\t--------------\n\n"
				 "\tPSRF Spooler Directory  -> [%s] | DAQ Variable [%s] \n"
				 "\tPSRF Archive Direcotory -> [%s] | DAQ Variable [%s]\n"
				 "\tPSRF File Prefix -> [%s] | DAQ Variable [%s] \n"
				 "\tPSRF Operation mode [%d] | DAQ Variable [%d] \n",
				 "\tPSRF yaf prefix [%c] | DAQ Variable [%c] \n",
				 "\tPSRF yaf prefix separator [%c] | DAQ Variable [%c] \n",
				 
				 i_psctx->pcap_reference_file,
				 i_psctx->pcap_reference.spooler_directory,i_psctx->spooler_directory,
				 i_psctx->pcap_reference.archive_directory,i_psctx->archive_directory,
				 i_psctx->pcap_reference.file_prefix,i_psctx->file_prefix,
				 i_psctx->pcap_reference.operation_mode,i_psctx->operation_mode,
				 i_psctx->pcap_reference.yaf_separator,i_psctx->yaf_separator,
				 i_psctx->pcap_reference.yaf_prefix_separator,i_psctx->yaf_prefix_separator);
	return 1;
    }
    
    return 0;
}


/* 
   Default uninitialized values, 
   people should be carefull if they want to run multiple instance in this context... 
*/
static u_int32_t pcap_spooler_default(pcap_spooler_context *i_psctx)
{
    if(i_psctx == NULL)
    {
	return 1;
    }

    if(i_psctx->operation_mode  == 0)
    {
	i_psctx->operation_mode = OPERATION_MODE_PCAP;
    }
    
    if(i_psctx->file_prefix == NULL)
    {
	switch(i_psctx->operation_mode)
	{
	case OPERATION_MODE_YAF:

	    /* Should not change */
	    i_psctx->yaf_separator = '_';
	    
	    if(i_psctx->yaf_prefix_separator == '0')
	    {
		i_psctx->yaf_prefix_separator = '_';
	    }
	    else
	    {
		pcap_spooler_debug_print(i_psctx,(char *)
					 "YAF prefix separator is : [%c] \n",
					 i_psctx->yaf_prefix_separator);
	    }

	    if(i_psctx->yaf_prefix != NULL)
	    {
		if( (i_psctx->file_prefix = strndup(i_psctx->yaf_prefix,PATH_MAX)) == NULL)
                {
                    return 1;
                }
	    }
	    else
		if( (i_psctx->file_prefix = strndup(DEFAULT_PCAP_SPOOLER_YAF_PREFIX,PATH_MAX)) == NULL)
		{
		    return 1;
		}

	    break;


	default:
	    if( (i_psctx->file_prefix = strndup(DEFAULT_PCAP_SPOOLER_FILE_PREFIX,PATH_MAX)) == NULL)
	    {
		return 1;
	    }
	    break;
	}
    }

    if(i_psctx->spooler_directory == NULL)
    {
	if( (i_psctx->spooler_directory = strndup(DEFAULT_PCAP_SPOOLER_SPOOL_DIRECTORY,PATH_MAX)) == NULL)
	{
	    return 1;
	}
    }

    if(i_psctx->archive_directory == NULL)
    {
	if( (i_psctx->archive_directory = strndup(DEFAULT_PCAP_SPOOLER_ARCHIVE_DIRECTORY,PATH_MAX)) == NULL)
	{
	    return 1;
	}
    }
    
    
    if(i_psctx->pcap_reference_file == NULL)
    {
	if( (i_psctx->pcap_reference_file = strndup(DEFAULT_PCAP_SPOOLER_REFERENCE_FILE,PATH_MAX)) == NULL)
	{
	    return 1;
	}
    }
    
    if(i_psctx->pcap_update_window == 0)
    {
	i_psctx->pcap_update_window = DEFAULT_PCAP_SPOOLER_UPDATE_WINDOW;
	
    }
    
    if(i_psctx->enable_archive == 0)
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\tArchive mode disabled \n");
    }
    
    if(i_psctx->block_size_read == 0)
    {
	i_psctx->block_size_read = DEFAULT_PCAP_SPOOLER_BLOCK_MULTIPLE;
    }
    
    return 0;
}



static u_int32_t pcap_spooler_initialize(pcap_spooler_context *i_psctx)
{

    DIR *tdir = NULL;
        
    if(i_psctx == NULL)
    {
	return 1;
    }
    
    
    /* Check if we can access everything */
    if( (tdir = opendir(i_psctx->spooler_directory)) == NULL)
    {
	pcap_spooler_debug_print(i_psctx,(char *)
				 "\t[%s]: Unable to open [%s] \n",
				 __FUNCTION__,
				 i_psctx->spooler_directory);
	return 1;
    }
    else
    {
	i_psctx->spooler_dir = tdir;
	tdir = NULL;
    }
    
    if(i_psctx->enable_archive)
    {
         if( (tdir = opendir(i_psctx->archive_directory)) == NULL)
         {
       	     pcap_spooler_debug_print(i_psctx,(char *)
			     	      "\t[%s]: Unable to open [%s] \n",
                                          __FUNCTION__,
                                         i_psctx->archive_directory);
	     return 1;
         }
   
         closedir(tdir);
         tdir = NULL;
    }
    
    /* Open Packt Reference */
    if( pcap_spooler_open_pcap_reference(i_psctx))
    {
	if( (pcap_spooler_create_pcap_reference(i_psctx)))
	{
	    pcap_spooler_debug_print(i_psctx,(char *)
				     "\t[%s]: Unable to create [%s] \n",
				     __FUNCTION__,
				     i_psctx->pcap_reference_file);
	    return 1;
	}
    }
    else
    {
	if(pcap_spooler_compare_pcap_reference(i_psctx))
	{
	    return 1;	
	}
	
	/* We are already have a file lets see */
	if( i_psctx->pcap_reference.timestamp !=0 )
	{
	    if(pcap_spooler_open_pcap(i_psctx))
	    {
		pcap_spooler_debug_print(i_psctx,(char *)
					 "\t[%s]: Unable to open current file, will monitor directory for activity.\n",
					 __FUNCTION__);
	    }
	}
    }

    i_psctx->state=DAQ_STATE_INITIALIZED;    
    return 0;
}


/*
  Initialize context from arguemnt and default if needed
*/
static int pcap_spooler_parse_args(pcap_spooler_context *i_psctx,const DAQ_Config_t * config,void **ctxt_ptr)
{
    
    DAQ_Dict *entry = NULL;    
    
    unsigned int str_len = 0;

    if( (i_psctx == NULL)  ||
	(config == NULL)   ||
	(ctxt_ptr == NULL))
    {
	return DAQ_ERROR;
    }
    
    for (entry = config->values; entry; entry = entry->next)
    {
	str_len = 0;
	
	if (!strcmp(entry->key, "file_prefix"))
	{
	    if( (i_psctx->file_prefix = strndup(entry->value,PATH_MAX)) == NULL)
	    {
		return DAQ_ERROR;
	    }
	}

	if (!strcmp(entry->key, "spool_directory"))
	{
	    
	    str_len = strlen(entry->value);
	    if(str_len > PATH_MAX)
	    {
		return DAQ_ERROR;
	    }
	    else
	    {
		if(entry->value[str_len] == '\\')
		{
		    entry->value[str_len] = 0x00;
		}
	    }

	    
	    if( (i_psctx->spooler_directory = strndup(entry->value,PATH_MAX)) == NULL)
	    {
		return DAQ_ERROR;
	    }
	}
	
	if (!strcmp(entry->key, "archive_directory"))
	{
	    
	    str_len = strlen(entry->value);
	    if(str_len > PATH_MAX)
	    {
		return DAQ_ERROR;
	    }
	    else
	    {
		if(entry->value[str_len] == '\\')
		{
		    entry->value[str_len] = 0x00;
		}
	    }
	    	    
	    if( (i_psctx->archive_directory = strndup(entry->value,PATH_MAX)) == NULL)
	    {
		return DAQ_ERROR;
	    }
	}
	
	if (!strcmp(entry->key, "pcap_reference_file"))
	{
	    if( (i_psctx->pcap_reference_file = strndup(entry->value,PATH_MAX)) == NULL)
            {
                return DAQ_ERROR;
            }
	}
	
	if (!strcmp(entry->key, "pcap_update_window"))
	{
	    if( (i_psctx->pcap_update_window = strtoul(entry->value,NULL,10)) == 0)
	    {
		return DAQ_ERROR;
	    }
	}

	if (!strcmp(entry->key, "block_size_read"))
	{
	    if( (i_psctx->block_size_read = strtoul(entry->value,NULL,10)) == 0)
	    {
		return DAQ_ERROR;
	    }
	}
	
	if (!strcmp(entry->key, "enable_archive"))
	{
	    if( (i_psctx->enable_archive = strtoul(entry->value,NULL,10)) == 0)
	    {
		return DAQ_ERROR;
	    }
	}

	if (!strcmp(entry->key, "enable_debug"))
	{
	    if( (i_psctx->enable_debug = strtoul(entry->value,NULL,10)) == 0)
	    {
		return DAQ_ERROR;
	    }
	}
	
	if (!strcmp(entry->key, "yaf_prefix"))
        {
	    if( (i_psctx->yaf_prefix = strndup(entry->value,PATH_MAX)) == NULL)
            {
                return DAQ_ERROR;
            }
	}

	if (!strcmp(entry->key, "yaf_prefix_separator"))
        {
	    
	    if((memcpy(&i_psctx->yaf_prefix_separator,entry->value,sizeof(char))) != &i_psctx->yaf_prefix_separator)
	    {
		return DAQ_ERROR;
	    }
	}


	if (!strcmp(entry->key, "operation_mode"))
	{
	    char *def_mode = NULL;
	    
	    if( (def_mode = strndup(entry->value,32)) == NULL)
	    {
		return DAQ_ERROR;
	    }
	    
	    if( (strncasecmp(def_mode,"pcap",32) == 0))
	    {
		i_psctx->operation_mode = OPERATION_MODE_PCAP;
	    }
	    else if( (strncasecmp(def_mode,"yaf",32) == 0))
	    {
		i_psctx->operation_mode = OPERATION_MODE_YAF;
	    }
	    else
	    {
		free(def_mode);
		return DAQ_ERROR;
	    }
	    
	    free(def_mode);
	}
    }
    
    if(pcap_spooler_default(i_psctx))
    {
	return DAQ_ERROR;
    }
    
    
    if(pcap_spooler_initialize(i_psctx))
    {
	return DAQ_ERROR;
    }

    
    return DAQ_SUCCESS;
}


static u_int32_t pcap_spooler_move_pcap(pcap_spooler_context *i_psctx)
{
    
    char old_path[PATH_MAX] = {0};
    char new_path[PATH_MAX] = {0};
    
    /* YAF */
    char yaf_timestamp_str[15] = {0};
    /* YAF */

    if(i_psctx == NULL)
    {
	return 1;
    }
    

    switch(i_psctx->operation_mode)
    {
    case OPERATION_MODE_YAF:
	if( (pcap_spooler_yaf_utc_to_timestamp((time_t)i_psctx->pcap_reference.timestamp,yaf_timestamp_str)))
	{
	    return 1;
	}
	
	if( (snprintf(old_path,PATH_MAX,"%s/%s%c%s%c%.llu.pcap",
		      i_psctx->pcap_reference.spooler_directory,
		      i_psctx->pcap_reference.file_prefix,
		      i_psctx->pcap_reference.yaf_prefix_separator,
		      yaf_timestamp_str,
		      i_psctx->pcap_reference.yaf_separator,
		      i_psctx->pcap_reference.serial)) < 0)
	{
	    return 1;
	}
	
	if( (snprintf(new_path,PATH_MAX,"%s/%s%c%s%c%.llu.pcap",
		      i_psctx->pcap_reference.archive_directory,
		      i_psctx->pcap_reference.file_prefix,
                      i_psctx->pcap_reference.yaf_prefix_separator,
                      yaf_timestamp_str,
                      i_psctx->pcap_reference.yaf_separator,
                      i_psctx->pcap_reference.serial)) < 0)
	{
	    return 1;
	}
	break;
	
    default:
	if( (snprintf(old_path,PATH_MAX,"%s/%s.%u",
		      i_psctx->pcap_reference.spooler_directory,
		      i_psctx->pcap_reference.file_prefix,
		      i_psctx->pcap_reference.timestamp)) < 0)
	{
	    return 1;
	}
	
	
	if( (snprintf(new_path,PATH_MAX,"%s/%s.%u",
		      i_psctx->pcap_reference.archive_directory,
		  i_psctx->pcap_reference.file_prefix,
		      i_psctx->pcap_reference.timestamp)) < 0)
	{
	    return 1;
	}
	break;
    }
    
    pcap_spooler_debug_print(i_psctx,(char *)
			     "\tMoving file [%s] to [%s] \n",
			     old_path,new_path);
    
    if( rename(old_path,new_path) <0)
    {
	return 1;
    }
    
    return 0;
}

static int pcap_spooler_directory_filter(const struct dirent *pcap_file_comp)
{
    unsigned int pcap_file_prefix_len = 0;
    
    if(pcap_file_comp == NULL)
    {
	return 0;
    }
    
    if(pcap_file_comp->d_type != DT_REG)
    {
	return 0;
    }
    
    pcap_file_prefix_len = strlen(pcap_file_prefix);
    
    switch(dir_filter_op_mode)
    {
    case OPERATION_MODE_YAF:
	
	if(strncmp(pcap_file_comp->d_name,pcap_file_prefix,pcap_file_prefix_len) == 0 )
	{
	    /* Ignore lock files */
	    if( strstr(pcap_file_comp->d_name,".lock") == NULL)
		return 1;
	}
	break;
	
    default:
	if(strncmp(pcap_file_prefix,pcap_file_comp->d_name,pcap_file_prefix_len) == 0)
	{
	    return 1;
	}
	break;
    }
    
    return 0;
}


static u_int32_t pcap_spooler_yaf_timestamp_to_utc(char *timestamp,time_t *out_utc)
{
    if( (timestamp == NULL) || 
	(out_utc == NULL))
    {
	return 1;
    }

    struct tm ltime;

    memset(&ltime,'\0',sizeof(struct tm));

    char temp_store[5] = {0};
    
    memset(temp_store,'\0',5);
    memcpy(temp_store,timestamp,4);
    ltime.tm_year = strtoul(temp_store,NULL,10);    

    ltime.tm_year = ltime.tm_year - 1900;

    memset(temp_store,'\0',5);
    memcpy(temp_store,&timestamp[4],2);
    ltime.tm_mon =  strtoul(temp_store,NULL,10);    

    memset(temp_store,'\0',5);
    memcpy(temp_store,&timestamp[6],2);
    ltime.tm_mday = strtoul(temp_store,NULL,10);

    memset(temp_store,'\0',5);
    memcpy(temp_store,&timestamp[8],2);
    ltime.tm_hour = strtoul(temp_store,NULL,10);

    memset(temp_store,'\0',5);
    memcpy(temp_store,&timestamp[10],2);
    ltime.tm_min =strtoul(temp_store,NULL,10);

    memset(temp_store,'\0',5);
    memcpy(temp_store,&timestamp[12],2);
    ltime.tm_sec = strtoul(temp_store,NULL,10);

    if( (*out_utc = timegm(&ltime)) < 0)
    {
	return 1;
    }

    return 0;
}

static u_int32_t pcap_spooler_yaf_utc_to_timestamp(time_t in_utc,char *out_timestamp)
{
    if(out_timestamp == NULL)
    {
	return 1;
    }

    struct tm ltime;

    if( (gmtime_r(&in_utc,&ltime)) == NULL)
    {
	return 1;
    }

    snprintf(out_timestamp,16,"%d%.2d%.2d%.2d%.2d%.2d",
	     ltime.tm_year+1900,
	     ltime.tm_mon,
	     ltime.tm_mday,
	     ltime.tm_hour,
	     ltime.tm_min,
	     ltime.tm_sec);
    
    return 0;
}


static u_int32_t pcap_spooler_monitor_directory(pcap_spooler_context *i_psctx)
{
    struct dirent **pcap_file_list = NULL;
    
    int num_file = 0;
    int x = 0;    
    
    int new_file_check = 0;
    
    unsigned long int current_stamp = 0;
    unsigned long int min_stamp = 0;

    unsigned long int prefix_len = 0;
    
    /* YAF */
    unsigned long long int  min_serial = 0;
    char yaf_serial_str[20] = {0}; /* the serial size has grown in version 2.5 should be fine for a while..*/
    char yaf_timestamp_str[15] = {0};
    
    unsigned long long int yaf_serial = 0;
    unsigned int yaf_timestamp = 0;

    char *st_field_sep = NULL;
    char *nd_field_sep = NULL;
    char *ext_ptr = NULL;
    /* YAF */
    
    if(i_psctx == NULL)
    {
	goto f_err;
    }
    
    if( (num_file = scandir(i_psctx->pcap_reference.spooler_directory,
			    &pcap_file_list,
	                    pcap_spooler_directory_filter,
			    &alphasort)) < 0 )
    {
	goto f_err;
    }
    
    for(x = 0; x < num_file; x++)
    {
	switch(i_psctx->operation_mode)
	{
	case OPERATION_MODE_YAF:
	    
	    if( (st_field_sep = index(pcap_file_list[x]->d_name,i_psctx->yaf_prefix_separator)) == NULL)
	    {
		pcap_spooler_debug_print(i_psctx,(char *)
					 "[%s()]: can't decode filename [%s], aborting... \n",
					 __FUNCTION__,
					 pcap_file_list[x]->d_name);
		abort();
	    }

	    
	    if( (size_t)(st_field_sep - pcap_file_list[x]->d_name) > strlen(i_psctx->file_prefix))
	    {
		pcap_spooler_debug_print(i_psctx,(char *)
					 "[%s()]: Distance betwen defined prefix and occurence of the first separator is to large for file [%s], aborting... \n",
					 __FUNCTION__,
					 pcap_file_list[x]->d_name);
		abort();
	    }


	    if( (nd_field_sep = index((char *)(st_field_sep+1),i_psctx->yaf_separator)) == NULL)
	    {
		pcap_spooler_debug_print(i_psctx,(char *)
					 "[%s()]: can't decode filename [%s], aborting... \n",
					 __FUNCTION__,
					 pcap_file_list[x]->d_name);
		abort();
	    }

	    char ext_dot = '.';
	    if( (ext_ptr = index((char *)(nd_field_sep+1),ext_dot)) == NULL)
	    {
		pcap_spooler_debug_print(i_psctx,(char *)
					 "[%s()]: can't decode filename [%s], aborting... \n",
					 __FUNCTION__,
					 pcap_file_list[x]->d_name);
		abort();
	    }
	    
	    memcpy(yaf_timestamp_str,(st_field_sep+1),(nd_field_sep - (st_field_sep+1)));
	    memcpy(yaf_serial_str,(nd_field_sep+1),((ext_ptr - 1) - nd_field_sep ));
	    
	    yaf_serial = strtoull(yaf_serial_str,'\0',10);
	    
	    if( (pcap_spooler_yaf_timestamp_to_utc(yaf_timestamp_str,(time_t *)&yaf_timestamp)))
	    {
		return 1;
	    }
	    
	    current_stamp = yaf_timestamp;
	    break;
	    
	default:
	    prefix_len = strlen(pcap_file_prefix) + 1;
	    current_stamp = strtoul(&pcap_file_list[x]->d_name[prefix_len],NULL,10);
	    break;
	}
	
	
	switch(i_psctx->operation_mode)
	{
	case OPERATION_MODE_YAF:
	    if(min_stamp == 0 &&
	       ((current_stamp > i_psctx->pcap_reference.timestamp) ||
		((current_stamp == i_psctx->pcap_reference.timestamp) && (yaf_serial > i_psctx->pcap_reference.serial))))
	    {
		min_stamp = current_stamp;
		min_serial = yaf_serial;
	    }
	    break;
	    
	default:
	    if( (min_stamp == 0)  &&
		(current_stamp > i_psctx->pcap_reference.timestamp))
	    {
		min_stamp = current_stamp;
	    }
	    break;
	}
	
	
	switch(i_psctx->operation_mode)
	{
	case OPERATION_MODE_YAF:
	    if( ((current_stamp <  min_stamp) ||
		 ((current_stamp ==  min_stamp) && (yaf_serial < min_serial))))
	    {
		min_stamp = current_stamp;
		min_serial = yaf_serial;
	    }  
	    break;

	default:
	    if( (current_stamp <= min_stamp))
	    {
		min_stamp = current_stamp;
	    }
	    break;
	}
    
    }        
    
    
    switch(i_psctx->operation_mode)
    {
    case OPERATION_MODE_YAF:
	if( (min_stamp > i_psctx->pcap_reference.timestamp) ||
	    ((min_stamp == i_psctx->pcap_reference.timestamp) && (min_serial > i_psctx->pcap_reference.serial)))
	{
	    new_file_check = 1;
	}
	
	break;
	
    default:
	if(min_stamp > i_psctx->pcap_reference.timestamp)
	{
	    new_file_check = 1;
	}
	break;
    }
    
    if((new_file_check))
    {
	if((i_psctx->has_PCAP) &&
	   (i_psctx->read_full))
	{
	    i_psctx->read_full = 0;
	    
	    if(i_psctx->enable_archive)
	    {
		if(pcap_spooler_move_pcap(i_psctx))
		{
		    goto f_err;
		}
	    }
	    
	    if( pcap_spooler_close_pcap(i_psctx))
	    {
		goto f_err;
	    }
	}
	
	switch(i_psctx->operation_mode)
	{
	case OPERATION_MODE_YAF:
	    i_psctx->pcap_reference.timestamp = min_stamp;
	    i_psctx->pcap_reference.serial = min_serial;    
	    break;
	    
	default:
	    i_psctx->pcap_reference.timestamp = min_stamp;
	    break;
	}
	
	/* We are opening a new file, make sure that even if we would crash and write the PSRF that the PSRF is re-initialized */
	i_psctx->pcap_reference.last_read_offset = 0;
	i_psctx->pcap_reference.saved_size = 0;
	
	if( pcap_spooler_open_pcap(i_psctx))
	{
		goto f_err;
	}
	
	if( pcap_spooler_get_stat(i_psctx->pcap_fd,&i_psctx->pcap_stat))
	{
	    goto f_err;
	}
	
	i_psctx->pcap_reference.last_read_offset = lseek(i_psctx->pcap_fd,0,SEEK_CUR);
	i_psctx->pcap_reference.saved_size = i_psctx->pcap_stat.st_size;
	
	if( (pcap_spooler_write_pcap_reference(i_psctx)))
	{
	    goto f_err;
	}
    }
    else
    {
	/* in case its stalling for some reason */
	usleep(200);
    }
    
    if(pcap_file_list != NULL)
    {
	free(pcap_file_list);
    }
    
    return 0;
    
f_err:
    if(pcap_file_list != NULL)
    {
	free(pcap_file_list);
    }
    
    return 1;
}

/**
 **
 ** PCAP SPOOLER FUNCTIONS
 **
 **/


/**
 **
 ** DAQ FUNCTIONS 
 **
 **/

static int pcap_spooler_daq_initialize(const DAQ_Config_t * config, void **ctxt_ptr, char *errbuf, size_t len)
{
    
    pcap_spooler_context *ps_ctx = NULL;
    
    if( (config == NULL)   ||
	(ctxt_ptr == NULL) ||
	(errbuf == NULL)   ||
	(len == 0))
    {
	return DAQ_ERROR;
    }
    
    /* Initialize self */
    if( (ps_ctx = (pcap_spooler_context *)calloc(1,(sizeof(pcap_spooler_context)))) == NULL)
    {
	snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PCAP_SPOOLER  context!", __FUNCTION__);
	return DAQ_ERROR;
    }
    
    /* Parse Arguments */
    if(pcap_spooler_parse_args(ps_ctx,config,ctxt_ptr) < 0)
    {
	return DAQ_ERROR;
    }
    
    *ctxt_ptr = ps_ctx;
    return DAQ_SUCCESS;
}


static int pcap_spooler_daq_set_filter(void *handle, const char *filter)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    if(i_psctx == NULL || filter == NULL)
    {
	return DAQ_ERROR;
    }
    
    uint32_t defaultnet = 0xFFFFFF00;
    
    /* 
       If we are started and we do not find any pcap file, this will get invoked by snort and will give out an 
       error if snaplen is 0 (snaplen being taken from the capture file), thus we fake initialization, set recompile flag
       and once a file is opened we pcap_spooler_daq_set_filter ..once! we could do it for every file.
    */
    
    if(i_psctx->bpf_recompile_filter)
    {
	sfbpf_freecode(&i_psctx->bpf_filter);
	
	if( sfbpf_compile(i_psctx->snaplen,i_psctx->data_link_type,&i_psctx->bpf_filter,filter,1,defaultnet) < 0)
	{
            pcap_spooler_debug_print(i_psctx,(char *)
				     "\tError compiling BFP filter [%s]\n",
				     filter);
	    return DAQ_ERROR;
	}
	
	i_psctx->bpf_recompile_filter = 0;
    }
    else
    {
	if(i_psctx->snaplen == 0)
	{
	    i_psctx->snaplen = 1514; /* Default snap len */
	    i_psctx->bpf_recompile_filter = 1;
	    
	    if( (i_psctx->bpf_filter_backup = strndup(filter,strlen(filter))) == NULL)
	    {
		pcap_spooler_debug_print(i_psctx,(char *)
					 "\tError duplicating BFP filter string [%s]\n",
					 filter);
		return DAQ_ERROR;
	    }
	    
	}
	
	if( sfbpf_compile(i_psctx->snaplen,i_psctx->data_link_type,&i_psctx->bpf_filter,filter,1,defaultnet) < 0)
	{
            pcap_spooler_debug_print(i_psctx,(char *)
				     "\tError compiling BFP filter [%s]\n",
				     filter);
	    return DAQ_ERROR;
	}
    }
	
    return DAQ_SUCCESS;
}


static int pcap_spooler_daq_get_stats(void *handle, DAQ_Stats_t * stats)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    if(i_psctx == NULL)
    {
	return DAQ_ERROR;
    }
    
    memcpy(stats,&i_psctx->stats,sizeof(DAQ_Stats_t));
    
    return DAQ_SUCCESS;
}

static void pcap_spooler_daq_reset_stats(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    if(i_psctx != NULL)
    {
	memset(&i_psctx->stats,'\0',sizeof(DAQ_Stats_t));
    }
    
    return;
}


static int pcap_spooler_daq_start(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;
    
    pcap_spooler_daq_reset_stats(i_psctx);
    
    i_psctx->state = DAQ_STATE_STARTED;
    
    pcap_spooler_debug_print(i_psctx,(char *)
			     "\t--------------\n"
			     "\t[Information from DAQ Variables]\n"
			     "\t--------------\n"
			     "\t Spooler Directory  -> [%s]\n"
			     "\t Archive Direcotory -> [%s]\n"
			     "\t File Prefix -> [%s]\n"
			     "\t PCAP Spooler Reference File -> [%s]\n"
			     "\t PCAP Spooler Reference Window [%u]\n"
			     "\t BFP Filter [%s]\n"
			     "\t Enable Archive [%u]\n"
			     "\t--------------\n\n"
			     "\t--------------\n"
			     "\t[Information from PCAP spooler reference file] \n"
			     "\t--------------\n"
			     "\tSpooler Directory -> [%s] \n"
			     "\tArchive Directory -> [%s] \n"
			     "\tFile Prefix -> [%s] \n"
			     "\tProcessing Timestamp -> [%u] \n"
#ifdef LARGEFILE_SUPPORT
			     "\tLast read offset -> [%llu] \n"
#else
			     "\tLast read offset -> [%u] \n"
#endif
			     "\tLast saved spool file size-> [%u] \n"
			     "\t--------------\n",
			     i_psctx->spooler_directory,
			     i_psctx->archive_directory,
			     i_psctx->file_prefix,
			     i_psctx->pcap_reference_file,
			     i_psctx->pcap_update_window,
			     i_psctx->bpf_filter_backup ? i_psctx->bpf_filter_backup : "None",
			     i_psctx->enable_archive,
			     i_psctx->pcap_reference.spooler_directory,
			     i_psctx->pcap_reference.archive_directory,
			     i_psctx->pcap_reference.file_prefix,
			     i_psctx->pcap_reference.timestamp,
#ifdef LARGEFILE_SUPPORT
			     (u_int64_t)i_psctx->pcap_reference.last_read_offset,
#else
			     (u_int32_t)i_psctx->pcap_reference.last_read_offset,
#endif
			     (u_int32_t)i_psctx->pcap_reference.saved_size);
    
    return DAQ_SUCCESS;

}


static int pcap_spooler_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback,DAQ_Meta_Func_t metaback, void *user)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    struct pcap_pkthdr *pkthdrptr = NULL;

    DAQ_PktHdr_t hdr;
    DAQ_Verdict verdict;
    
    char *pdata = NULL;    

    u_int8_t pcap_rebuffer=0;
    u_int8_t packet_filter_eval=0;
    
    ssize_t total_size = 0;
    ssize_t read_size = 0;
    
    off_t current_offset = 0;
    off_t process_offset = 0;
    off_t off_read = 0;
    off_t last_processed_offset = 0;
    
    if( (i_psctx == NULL) ||
#ifdef HAVE_DAQ_ACQUIRE_WITH_META
	(callback == NULL) ||
	(metaback == NULL))
#else
	(callback == NULL))
#endif
    {
	return 1;
    }

if(i_psctx->has_PCAP)
{
    if( pcap_spooler_get_stat(i_psctx->pcap_fd,& i_psctx->pcap_stat))
    {
	return 1;
    }
    
    total_size = i_psctx->pcap_stat.st_size;
    
    if(i_psctx->pcap_reference.last_read_offset != 0)
    {
	current_offset = lseek(i_psctx->pcap_fd,i_psctx->pcap_reference.last_read_offset,SEEK_SET);
    }
    else
    {
	current_offset = lseek(i_psctx->pcap_fd,0,SEEK_CUR);
    }
    
    while(current_offset < total_size)
    {    
	if(pcap_spooler_read_bulk(i_psctx->pcap_fd,(void *)i_psctx->read_buffer,i_psctx->read_buffer_size,&read_size))
	{
	    return 1;
	}
	
	current_offset = lseek(i_psctx->pcap_fd,0,SEEK_CUR);
	process_offset = 0;
	off_read = 0;
	
	while(process_offset < read_size)
	    {
		packet_filter_eval = 1;
		pkthdrptr=(struct pcap_pkthdr *)(i_psctx->read_buffer+process_offset);
		
		if( (process_offset + (off_t)sizeof(struct pcap_pkthdr)) >= read_size)
		{
		    pcap_rebuffer=1;
		    break;
		}
		
		if( (process_offset + (off_t)sizeof(struct pcap_pkthdr)+pkthdrptr->caplen) > read_size)
		{
		    pcap_rebuffer=1;
		    break;
		}
		
		process_offset+=sizeof(struct pcap_pkthdr);
		
		pdata = (char *)(i_psctx->read_buffer+process_offset);
		
		process_offset+=pkthdrptr->caplen;
		
		/* Used to adjust read lengths for intermediate pcap_reference file write*/
		off_read +=pkthdrptr->caplen + sizeof(struct pcap_pkthdr);
		
		hdr.caplen = pkthdrptr->caplen;
		hdr.pktlen = pkthdrptr->len;
		hdr.ts.tv_sec = pkthdrptr->timesec;
		hdr.ts.tv_usec = pkthdrptr->timeusec;
		
		hdr.flags = 0;
		
		if(i_psctx->bpf_filter.bf_insns)
		{
		    if(!(packet_filter_eval = sfbpf_filter(i_psctx->bpf_filter.bf_insns,(u_char *)pdata,pkthdrptr->len,pkthdrptr->caplen)))
		    {
			i_psctx->stats.packets_filtered++;
		    }
		}
		
		if(packet_filter_eval)
		{
		    i_psctx->stats.packets_received++;
#ifdef HAVE_DAQ_ACQUIRE_WITH_META
		    verdict = metaback(user,&hdr,(u_char *)pdata);
#else
		    verdict = callback(user,&hdr,(u_char *)pdata);
#endif		        
		    /* Is this needed? */
		    if (verdict >= MAX_DAQ_VERDICT)
			verdict = DAQ_VERDICT_PASS;
		    
		    i_psctx->stats.verdicts[verdict]++;
		}
		
		i_psctx->read_packet++;
		
		if(i_psctx->read_packet == i_psctx->pcap_update_window)
		{
		    i_psctx->pcap_reference.last_read_offset += off_read;
		    
		    if( (pcap_spooler_get_stat(i_psctx->pcap_fd,& i_psctx->pcap_stat)))
		    {
			return 1;
		    }
		    
		    i_psctx->pcap_reference.saved_size = i_psctx->pcap_stat.st_size;
		    
		    if( (pcap_spooler_write_pcap_reference(i_psctx)))
		    {
			return 1;
		    }
		    
		    i_psctx->read_packet = 0;
		    off_read = 0;
		}
	    }
	
	if(pcap_rebuffer)
	{
	    pcap_rebuffer=0;
		
	    last_processed_offset = current_offset - (read_size -  process_offset);
	    
	    if( (i_psctx->pcap_reference.last_read_offset = lseek(i_psctx->pcap_fd,last_processed_offset,SEEK_SET)) < 0)
	    {
		return 1;
	    }
	    
	    if( (pcap_spooler_get_stat(i_psctx->pcap_fd,&i_psctx->pcap_stat)))
	    {
		return 1;
	    }
	    
	    i_psctx->pcap_reference.last_read_offset = last_processed_offset;
	    i_psctx->pcap_reference.saved_size = i_psctx->pcap_stat.st_size;
	    
	    
	    if( (pcap_spooler_write_pcap_reference(i_psctx)))
	    {
		/* XXX */
		return 1;
	    }
	    
	    current_offset = i_psctx->pcap_reference.last_read_offset;
	    usleep(20);
	}
	
	memset(i_psctx->read_buffer,'\0',i_psctx->read_buffer_size);
    }
}


if( (i_psctx->has_PCAP)) 
{
    if( (pcap_spooler_get_stat(i_psctx->pcap_fd,& i_psctx->pcap_stat)))
    {
	return 1;
    }
    
    if(total_size == current_offset)
    {
	i_psctx->read_full = 1;
	i_psctx->pcap_reference.last_read_offset = total_size;
    }
    else if( ((i_psctx->pcap_stat.st_size > i_psctx->pcap_reference.saved_size) ||
	      (i_psctx->pcap_stat.st_size > i_psctx->pcap_reference.last_read_offset)) &&
	     (i_psctx->read_packet == i_psctx->pcap_update_window))
    {
	i_psctx->read_packet=0;
	i_psctx->pcap_reference.saved_size = i_psctx->pcap_stat.st_size;
	
	if( (pcap_spooler_write_pcap_reference(i_psctx)))
	{
	    /* XXX */
	    return 1;
	}
    }
}

if( (pcap_spooler_monitor_directory(i_psctx)))
{
    return 1;
}

return 0;
}


static int pcap_spooler_daq_breakloop(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    if(i_psctx == NULL)
    {
	return DAQ_ERROR;
    }
    
    if( (pcap_spooler_get_stat(i_psctx->pcap_fd,& i_psctx->pcap_stat)))
    {
	return DAQ_ERROR;
    }
    
    i_psctx->pcap_reference.saved_size = i_psctx->pcap_stat.st_size;
    
    if( (pcap_spooler_write_pcap_reference(i_psctx)))
    {
	return DAQ_ERROR;
    }
    
    return DAQ_SUCCESS;
}

static int pcap_spooler_daq_stop(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    if( (pcap_spooler_get_stat(i_psctx->pcap_fd,& i_psctx->pcap_stat)))
    {
	return DAQ_ERROR;
    }

    i_psctx->pcap_reference.saved_size = i_psctx->pcap_stat.st_size;
    
    if( (pcap_spooler_write_pcap_reference(i_psctx)))
    {
	return DAQ_ERROR;
    }

    if(i_psctx->bpf_recompile_filter)
    {
        sfbpf_freecode(&i_psctx->bpf_filter);
    }    
    
    if(i_psctx->pcap_fd != 0)
    {
	close(i_psctx->pcap_fd);
	i_psctx->pcap_fd = -1;
    }
    
    if(i_psctx->packet_reference_fd != 0)
    {
	close(i_psctx->packet_reference_fd);
	i_psctx->packet_reference_fd = -1;
    }

    if(i_psctx->spooler_dir != NULL)
    {
	closedir(i_psctx->spooler_dir);
	i_psctx->spooler_dir = NULL;
    }
    
    if(i_psctx->read_buffer != NULL)
    {
	free(i_psctx->read_buffer);
	i_psctx->read_buffer = NULL;
    }
    
    if(i_psctx != NULL)
    {
	free(i_psctx);
    }

    return DAQ_SUCCESS;
}


static void pcap_spooler_daq_shutdown(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    if( (pcap_spooler_get_stat(i_psctx->pcap_fd,& i_psctx->pcap_stat)))
    {
	return;
    }
    
    i_psctx->pcap_reference.saved_size = i_psctx->pcap_stat.st_size;

    if( (pcap_spooler_write_pcap_reference(i_psctx)))
    {
	return;
    }

    if(i_psctx->bpf_recompile_filter)
    {
        sfbpf_freecode(&i_psctx->bpf_filter);
    }    
    
    if(i_psctx->pcap_fd != 0)
    {
	close(i_psctx->pcap_fd);
	i_psctx->pcap_fd = -1;
    }
    
    if(i_psctx->packet_reference_fd != 0)
    {
	close(i_psctx->packet_reference_fd);
	i_psctx->packet_reference_fd = -1;
    }
    
    if(i_psctx->spooler_dir != NULL)
    {
	closedir(i_psctx->spooler_dir);
	i_psctx->spooler_dir = NULL;
    }
    
    if(i_psctx->read_buffer != NULL)
    {
	free(i_psctx->read_buffer);
	i_psctx->read_buffer = NULL;
    }

    if(i_psctx != NULL)
    {
	free(i_psctx);
    }
    
    return;
}



static DAQ_State pcap_spooler_daq_check_status(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;
    
    if(i_psctx != NULL)
    {
	return i_psctx->state;
    }
    
    return DAQ_STATE_UNINITIALIZED;
}



static int pcap_spooler_daq_get_snaplen(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;

    if(i_psctx != NULL)
    {
	return i_psctx->snaplen;
    }

    return 0;
}


static const char *pcap_spooler_daq_get_errbuf(void *handle)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;
    
    if(i_psctx->errbuf != NULL)
    {
	return i_psctx->errbuf;	
    }
    
    return NULL;
}


static void pcap_spooler_daq_set_errbuf(void *handle, const char *string)
{
    pcap_spooler_context *i_psctx = (pcap_spooler_context *)handle;
    
    if (string != NULL)
        return;
    
    DPE(i_psctx->errbuf, "%s", string);
    
    return;
}

static uint32_t pcap_spooler_daq_get_capabilities(void *handle)
{
    return DAQ_PCAP_SPOOLER_CAPABILITIES;
}


/* COULD BE PROBLEMATIC */
static int pcap_spooler_daq_get_datalink_type(void *handle)
{
    /* Since this happen early in initialization that that without
       modification to library its impossible to resend the information
       we assume Ethernet. it will be in the documentation..
       We shouldn't assume ......*/
    return DLT_EN10MB;
}
/* COULD BE PROBLEMATIC */


#ifdef BUILDING_SO
static int pcap_spooler_daq_dummy_funct(void *handle, ...)
{
    return DAQ_ERROR_NOTSUP;
}
#endif 

/**
 **
 ** Unsupported 
 **
 ***/
/*
  static int pcap_spooler_daq_inject(void *handle, const DAQ_PktHdr_t * hdr, const uint8_t * packet_data,
  uint32_t len, int reverse)
  {
  return DAQ_ERROR_NOTSUP;
  }
  
  static int pcap_spooler_daq_get_device_index(void *handle, const char *device)
  {
  return DAQ_ERROR_NOTSUP;
  }
*/
/**
 **
 ** Unsupported 
 **
 ***/


/**
 ** DAQ FUNCTIONS 
 **
 **/





