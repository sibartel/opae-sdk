// Copyright(c) 2021, Intel Corporation
//
// Redistribution  and  use  in source  and  binary  forms,  with  or  without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of  source code  must retain the  above copyright notice,
//   this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
// * Neither the name  of Intel Corporation  nor the names of its contributors
//   may be used to  endorse or promote  products derived  from this  software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,  BUT NOT LIMITED TO,  THE
// IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT  SHALL THE COPYRIGHT OWNER  OR CONTRIBUTORS BE
// LIABLE  FOR  ANY  DIRECT,  INDIRECT,  INCIDENTAL,  SPECIAL,  EXEMPLARY,  OR
// CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT LIMITED  TO,  PROCUREMENT  OF
// SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE,  DATA, OR PROFITS;  OR BUSINESS
// INTERRUPTION)  HOWEVER CAUSED  AND ON ANY THEORY  OF LIABILITY,  WHETHER IN
// CONTRACT,  STRICT LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE  OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,  EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "fpgaperf_counter.h"

#ifndef __USE_GNU
#define __USE_GNU 1
#endif
#include <pthread.h>

#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#include <opae/fpga.h>
#include <opae/log.h>
#include <opae/properties.h>
#include <opae/utils.h>
#include "opae_int.h"


#define DFL_PERF_FME		"/sys/bus/pci/devices/*%x*:*%x*:*%x*.*%x*/fpga_region/region*/dfl-fme.*"

#define DFL_PERF_SYSFS		"/sys/bus/event_source/devices"

/* This filter removes the unwanted events during enumeration */
#define EVENT_FILTER		{"clock", "fab_port_mmio_read", "fab_port_mmio_write", "fab_port_pcie0_read", "fab_port_pcie0_write"}

#define	DFL_PERF_STR_MAX	256

#define DFL_BUFSIZ_MAX		512

/* mutex to protect fpga perf pmu data structures */
pthread_mutex_t fpga_perf_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

/* Read format structure*/
struct read_format {
	uint64_t nr;
	struct {
		uint64_t value;
		uint64_t id;
	} values[];
};

typedef struct {
	char event_name[DFL_PERF_STR_MAX];
	uint64_t config;
	int fd;
	uint64_t id;
	uint64_t start_value;
	uint64_t stop_value;
} perf_event_type;

typedef struct {
	char format_name[DFL_PERF_STR_MAX];
	uint64_t shift;
} perf_format_type;

typedef struct {
	char dfl_fme_name[DFL_PERF_STR_MAX];
	int type;
	int cpumask;
	uint64_t num_format;
	perf_format_type *format_type;
	uint64_t num_perf_events;
	perf_event_type *perf_events;
} fpga_perf_counter;

/* Not static so other tools can access the PMU data */
fpga_perf_counter *g_fpga_perf = NULL;


/* provides number of files in the directory 
 * after removing unwanted files provided in filter */
uint64_t get_num_files(DIR *dir, char **filter, uint64_t filter_size)
{
	uint64_t loop		= 0;
	uint64_t num_files	= 0;
	struct dirent *entry	= NULL;

	while ((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		for (loop = 0; loop < filter_size; loop++) {
			if (!strcmp(entry->d_name, filter[loop]))
				break;
		}
		/* if matched with filter then check next file */
		if (loop != filter_size)
			continue;
		num_files++;
	}
	return num_files;
}

/* parse the each format and get the shift val */
fpga_result parse_Perf_Format(DIR *dir, char *dir_name)
{
	uint64_t format_num		= 0;
	int result			= -1;
	int res				= 0;
	struct dirent *format_entry	= NULL;
	FILE *file			= NULL;
	char sysfspath[DFL_BUFSIZ_MAX]	= { 0,};

	if (!dir || !dir_name) {
		OPAE_ERR("Invalid Input parameters");
		return FPGA_INVALID_PARAM;
	}

	if (opae_mutex_lock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to lock perf mutex");
		return FPGA_EXCEPTION;
	}
	g_fpga_perf->format_type = calloc(g_fpga_perf->num_format,
				sizeof(perf_format_type));
	if (!g_fpga_perf->format_type) {
		g_fpga_perf->num_format = 0;
		opae_mutex_unlock(res, &fpga_perf_lock);
		return FPGA_EXCEPTION;
	}

	rewinddir(dir);
	while ((format_entry = readdir(dir)) != NULL) {
		if (!strcmp(format_entry->d_name, ".") ||
			!strcmp(format_entry->d_name, ".."))
			continue;

		if (snprintf(g_fpga_perf->format_type[format_num].format_name,
			sizeof(g_fpga_perf->format_type[format_num].format_name),
						"%s", format_entry->d_name) < 0) {
			opae_mutex_unlock(res, &fpga_perf_lock);
			OPAE_ERR("snprintf buffer overflow");
			return FPGA_EXCEPTION;
		}

		if (snprintf(sysfspath, sizeof(sysfspath), "%s/format/%s",
					dir_name, format_entry->d_name) < 0) {
			opae_mutex_unlock(res, &fpga_perf_lock);
			OPAE_ERR("snprintf buffer overflow");
			return FPGA_EXCEPTION;
		}

		file = fopen(sysfspath, "r");
		if (file != NULL) {
			result = fscanf(file, "config:%ld",
				&g_fpga_perf->format_type[format_num].shift);

			/*read config first byte success*/
			if (result == -1) {
				OPAE_ERR("Failed to read %s", sysfspath);
				fclose(file);
				opae_mutex_unlock(res, &fpga_perf_lock);
				return FPGA_EXCEPTION;
			}
			fclose(file);
		} else {
			opae_mutex_unlock(res, &fpga_perf_lock);
			return FPGA_EXCEPTION;
		}
		if (format_num == g_fpga_perf->num_format)
			break;
		format_num++;
	}
	if (opae_mutex_unlock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to unlock perf mutex");
		return FPGA_EXCEPTION;
	}
	return FPGA_OK;
}

/* parse the event value and get the type specific config value*/
uint64_t parse_event(char *value)
{
	uint64_t loop		= 0;
	int num 		= 0;
	uint64_t config 	= 0;
	char *name_evt_str 	= NULL;
	char *sub_str 		= strtok(value, ",");
	long val		= 0;

	while (sub_str != NULL) {
		for (loop = 0; loop < g_fpga_perf->num_format; loop++) {
			name_evt_str = strstr(sub_str,
				g_fpga_perf->format_type[loop].format_name);
			if (name_evt_str) {
				num = strlen(g_fpga_perf->format_type[loop].format_name);
				/* Ignore '=0x' and convert to hex */
				val = strtol(sub_str+num+3, NULL, 16);
				config |= (val << g_fpga_perf->format_type[loop].shift);
			}

		}
		sub_str = strtok(NULL, ",");
	}

	return config;
}

/* parse the evnts for the perticular device directory */
fpga_result parse_Perf_Event(DIR *dir, char **filter, uint64_t filter_size, char *dir_name)
{
	uint64_t loop				= 0;
	uint64_t generic_num			= 0;
	int result				= -1;
	int res					= 0;
	struct dirent *event_entry 		= NULL;
	FILE *file 				= NULL;
	char sysfspath[DFL_BUFSIZ_MAX] 		= { 0,};
	char event_value[DFL_BUFSIZ_MAX] 	= { 0,};
	
	if (!dir || !dir_name) {
		OPAE_ERR("Invalid Input parameters");
		return FPGA_INVALID_PARAM;
	}

	if (opae_mutex_lock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to lock perf mutex");
		return FPGA_EXCEPTION;
	}
	g_fpga_perf->perf_events = calloc(g_fpga_perf->num_perf_events,
						sizeof(perf_event_type));
	if (!g_fpga_perf->perf_events) {
		opae_mutex_lock(res, &fpga_perf_lock);
		g_fpga_perf->num_perf_events = 0;
		return FPGA_EXCEPTION;
	}

	rewinddir(dir);
	while ((event_entry = readdir(dir)) != NULL) {
		if (!strcmp(event_entry->d_name, ".") ||
				!strcmp(event_entry->d_name, ".."))
			continue;
		for (loop = 0; loop < filter_size; loop++) {
			if (!strcmp(event_entry->d_name, filter[loop]))
				break;
		}
		if (loop != filter_size)
			continue;

		if (snprintf(g_fpga_perf->perf_events[generic_num].event_name,
			sizeof(g_fpga_perf->perf_events[generic_num].event_name),
						"%s", event_entry->d_name) < 0) {
			OPAE_ERR("snprintf buffer overflow");
			opae_mutex_lock(res, &fpga_perf_lock);
			return FPGA_EXCEPTION;
		}
	
		if (snprintf(sysfspath, sizeof(sysfspath), "%s/events/%s",
						dir_name, event_entry->d_name) < 0) {
			OPAE_ERR("snprintf buffer overflow");
			opae_mutex_lock(res, &fpga_perf_lock);
			return FPGA_EXCEPTION;
		}
			
		file = fopen(sysfspath, "r");
		if (file != NULL) {
			result = fscanf(file, "%s", event_value);
			/* read event_value success*/
			if (result == 1) {

				g_fpga_perf->perf_events[generic_num].config
						= parse_event(event_value);

			} else {
				opae_mutex_unlock(res, &fpga_perf_lock);
				return FPGA_EXCEPTION;
			}
			fclose(file);
		} else {
			opae_mutex_unlock(res, &fpga_perf_lock);
			return FPGA_EXCEPTION;
		}
		if (generic_num == g_fpga_perf->num_perf_events)
			break;
		generic_num++;
	}
	if (opae_mutex_unlock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to unlock perf mutex");
		return FPGA_EXCEPTION;
	}
	return FPGA_OK;
}

/* read the type and cpumask from the sysfs path */
fpga_result read_perf_sysfs(char *sysfs_path, int *val)
{
        FILE *file = NULL;

        file = fopen(sysfs_path, "r");
        if (!file) {
		OPAE_ERR("fopen(%s) failed\n", sysfs_path);
                return FPGA_NOT_FOUND;
        }
        if(1 != fscanf(file,  "%d", val)) {
		OPAE_ERR("Failed to read %s", sysfs_path);
		fclose(file);
                return FPGA_EXCEPTION;
        }
        fclose(file);
        return FPGA_OK;
}

/* get fpga sbdf from token */
fpga_result get_Fpga_Sbdf(fpga_token token,
                uint16_t *segment,
                uint8_t *bus,
                uint8_t *device,
                uint8_t *function)
{
        fpga_result res = FPGA_OK;
        fpga_properties props = NULL;

        if (!segment || !bus ||
                !device || !function) {
                OPAE_ERR("Invalid input parameters");
                return FPGA_INVALID_PARAM;
        }
        res = fpgaGetProperties(token, &props);
        if (res != FPGA_OK) {
                OPAE_ERR("Failed to get properties ");
                return res;
        }
        res = fpgaPropertiesGetBus(props, bus);
        if (res != FPGA_OK) {
                OPAE_ERR("Failed to get bus ");
                return res;
        }
        res = fpgaPropertiesGetSegment(props, segment);
        if (res != FPGA_OK) {
                OPAE_ERR("Failed to get Segment ");
                return res;
        }
        res = fpgaPropertiesGetDevice(props, device);
        if (res != FPGA_OK) {
                OPAE_ERR("Failed to get Device ");
                return res;
        }
        res = fpgaPropertiesGetFunction(props, function);
        if (res != FPGA_OK) {
                OPAE_ERR("Failed to get Function ");
                return res;
        }

        return res;
}


fpga_result fpga_Perf_Events(char *dfl_sysfs)
{
	fpga_result ret				= FPGA_OK;
	struct perf_event_attr pea;
	int fd					= -1;
	int grpfd				= 0;
	DIR *dir				= NULL;
	DIR *event_dir				= NULL;
	DIR *format_dir				= NULL;
	struct dirent *entry			= NULL;
	char dir_name[DFL_PERF_STR_MAX] 	= { 0,};
	char event_path[DFL_BUFSIZ_MAX]		= { 0,};
	char sysfspath[DFL_BUFSIZ_MAX]		= { 0,};
	char format_path[DFL_BUFSIZ_MAX]	= { 0,};
	char *event_filter[]			= EVENT_FILTER;
	uint64_t loop				= 0;
	int res					= 0;
	uint64_t format_size			= 0;
	uint64_t event_size			= 0;

	if (!dfl_sysfs) {
		OPAE_ERR("Invalid input paramters");
		return FPGA_INVALID_PARAM;
	}

	dir = opendir(dfl_sysfs);
	if (!dir) {
		OPAE_ERR("opendir(%s) failed\n", dfl_sysfs);
		ret = FPGA_EXCEPTION;
		goto out;
	}
	/* Add PMU */
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(g_fpga_perf->dfl_fme_name, entry->d_name) != 0)
			continue;
		else {
			if (opae_mutex_lock(res, &fpga_perf_lock)) {
				OPAE_MSG("Failed to lock perf mutex");
				ret = FPGA_EXCEPTION;
				goto out;
			}
			/* read name */
			if (snprintf(dir_name, sizeof(dir_name), "%s/%s",
					dfl_sysfs, g_fpga_perf->dfl_fme_name) < 0) {
				OPAE_ERR("snprintf buffer overflow");
				opae_mutex_unlock(res, &fpga_perf_lock);
				ret = FPGA_EXCEPTION;
				goto out;
			}
			/* read type */
			if (snprintf(sysfspath, sizeof(sysfspath), "%s/type",
								dir_name) < 0) {
				OPAE_ERR("snprintf buffer overflow");
				opae_mutex_unlock(res, &fpga_perf_lock);
				ret = FPGA_EXCEPTION;
				goto out;
			}	
			/* read the pmus type*/
			ret = read_perf_sysfs(sysfspath, &g_fpga_perf->type);
			if (ret != FPGA_OK) {
				ret = FPGA_EXCEPTION;
				opae_mutex_unlock(res, &fpga_perf_lock);
				goto out;
			}
 			/* read cpumask */
			if (snprintf(sysfspath, sizeof(sysfspath), "%s/cpumask",
							dir_name) < 0) {
				OPAE_ERR("snprintf buffer overflow");
				ret = FPGA_EXCEPTION;
				opae_mutex_unlock(res, &fpga_perf_lock);
				goto out;
			}		
			ret = read_perf_sysfs(sysfspath, &g_fpga_perf->cpumask);
			if (ret != FPGA_OK) {
				ret = FPGA_EXCEPTION;
				opae_mutex_unlock(res, &fpga_perf_lock);
				goto out;
			}
			if (opae_mutex_unlock(res, &fpga_perf_lock)) {
				OPAE_MSG("Failed to unlock perf mutex");
				ret = FPGA_EXCEPTION;
				goto out;
			}
			/* Scan format strings */
			if (snprintf(format_path, sizeof(format_path), "%s/format",
							dir_name) < 0) {
				OPAE_ERR("snprintf buffer overflow");
				ret = FPGA_EXCEPTION;
				goto out;
			}		
			format_dir = opendir(format_path);
			if (format_dir != NULL) {
				/* Count format strings and parse the format*/
				if (opae_mutex_lock(res, &fpga_perf_lock)) {
					OPAE_MSG("Failed to lock perf mutex");
					ret = FPGA_EXCEPTION;
					goto out;
				}
				g_fpga_perf->num_format = get_num_files(format_dir,
								NULL, format_size);
				if (opae_mutex_unlock(res, &fpga_perf_lock)) {
					OPAE_MSG("Failed to lock perf mutex");
					ret = FPGA_EXCEPTION;
					goto out;
				}
				ret = parse_Perf_Format(format_dir, dir_name);
				if (ret != FPGA_OK) {
					closedir(format_dir);
					ret = FPGA_EXCEPTION;
					goto out;
				}
				closedir(format_dir);
			} else {
				ret = FPGA_EXCEPTION;
				goto out;
			}
			if (snprintf(event_path, sizeof(event_path), "%s/events",
								dir_name) < 0) {
				OPAE_ERR("snprintf buffer overflow");
				ret = FPGA_EXCEPTION;
				goto out;
			}			
			event_dir = opendir(event_path);
			if (event_dir != NULL) {
				/* count generic events and parse the events*/
				event_size = sizeof(event_filter) / sizeof(event_filter[0]);
				if (opae_mutex_lock(res, &fpga_perf_lock)) {
					OPAE_MSG("Failed to lock perf mutex");
					ret = FPGA_EXCEPTION;
					goto out;
				}
				g_fpga_perf->num_perf_events = get_num_files(event_dir,
								event_filter, event_size);
	
				if (opae_mutex_unlock(res, &fpga_perf_lock)) {
					OPAE_MSG("Failed to unlock perf mutex");
					ret = FPGA_EXCEPTION;
					goto out;
				}
				ret = parse_Perf_Event(event_dir, event_filter,
							event_size, dir_name);
				if (ret != FPGA_OK) {
					closedir(event_dir);
					ret = FPGA_EXCEPTION;
					goto out;
				}
				closedir(event_dir);
			} else {
				ret = FPGA_EXCEPTION;
				goto out;
			}
		}
	}
	/* initialize the pea structure to 0 */
	memset(&pea, 0, sizeof(struct perf_event_attr));

	if (opae_mutex_lock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to lock perf mutex");
		ret = FPGA_EXCEPTION;
		goto out;
	}	
	for (loop = 0; loop < g_fpga_perf->num_perf_events; loop++) {
		if (g_fpga_perf->perf_events[0].fd <= 0)
			grpfd = -1;
		else
			grpfd = g_fpga_perf->perf_events[0].fd;
		if (!g_fpga_perf->perf_events[loop].config)
			continue;

		pea.type = g_fpga_perf->type;
		pea.size = sizeof(struct perf_event_attr);
		pea.config = g_fpga_perf->perf_events[loop].config;
		pea.disabled = 1;
		pea.inherit = 1;
		pea.sample_type = PERF_SAMPLE_IDENTIFIER;
		pea.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
		fd = syscall(__NR_perf_event_open, &pea, -1,
				g_fpga_perf->cpumask, grpfd, 0);
		if (fd == -1) {
			OPAE_ERR("Error opening leader %llx\n", pea.config);
			opae_mutex_unlock(res, &fpga_perf_lock);
			ret = FPGA_EXCEPTION;
			goto out;
		} else {
			g_fpga_perf->perf_events[loop].fd = fd;
			if (ioctl(g_fpga_perf->perf_events[loop].fd, PERF_EVENT_IOC_ID,
						&g_fpga_perf->perf_events[loop].id) == -1) {
				OPAE_ERR("PERF_EVENT_IOC_ID ioctl failed: %s",
									strerror(errno));
				opae_mutex_unlock(res, &fpga_perf_lock);
				ret = FPGA_EXCEPTION;
				goto out;
			}
		}
	}
	if (ioctl(g_fpga_perf->perf_events[0].fd, PERF_EVENT_IOC_RESET,
						PERF_IOC_FLAG_GROUP) == -1) {
		OPAE_ERR("PERF_EVENT_IOC_RESET ioctl failed: %s", strerror(errno));
		opae_mutex_unlock(res, &fpga_perf_lock);
		ret = FPGA_EXCEPTION;
		goto out;
	}
	if (opae_mutex_unlock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to unlock perf mutex");
		ret = FPGA_EXCEPTION;
		goto out;
	}
	closedir(dir);
	return ret;

out:
	closedir(dir);
	opae_mutex_unlock(res, &fpga_perf_lock);
	return ret;
}

/*Enumerate the dfl-fme based on the sbdf */
fpga_result fpgaPerfCounterEnum(fpga_token token)
{
	fpga_result ret                         = FPGA_OK;
        char sysfs_path[DFL_PERF_STR_MAX]       = { 0 };
        char sysfs_perf[DFL_PERF_STR_MAX]       = { 0 };
        int gres                                = 0;
        int res                                 = 0;
        uint32_t fpga_id                        = -1;
        char *endptr                            = NULL;
        glob_t pglob;
	uint8_t bus                             = (uint8_t)-1;
	uint16_t segment                        = (uint16_t)-1;
	uint8_t device                          = (uint8_t)-1;
	uint8_t function                        = (uint8_t)-1;

        res = get_Fpga_Sbdf(token, &segment, &bus, &device, &function);
        if (res != FPGA_OK) {
                OPAE_ERR("Failed to get sbdf ");
                return res;
        }

	/* when we bind with new device id we will get updated function value */
	/* not able to read the sysfs path using that */
	function = 0;

	if (snprintf(sysfs_path, sizeof(sysfs_path),
		DFL_PERF_FME,
		segment, bus, device, function) < 0) {
		OPAE_ERR("snprintf buffer overflow");
		return FPGA_EXCEPTION;
	}
        gres = glob(sysfs_path, GLOB_NOSORT, NULL, &pglob);
        if (gres) {
                OPAE_ERR("Failed pattern match %s: %s", sysfs_path, strerror(errno));
                globfree(&pglob);
                return FPGA_NOT_FOUND;
        }
        if (pglob.gl_pathc == 1) {
                char *ptr = strstr(pglob.gl_pathv[0], "fme");
                if (!ptr) {
                        ret = FPGA_INVALID_PARAM;
                        goto out;
                }
                errno = 0;
                fpga_id = strtoul(ptr + 4, &endptr, 10);

                if (opae_mutex_lock(res, &fpga_perf_lock)) {
                        OPAE_MSG("Failed to lock perf mutex");
                        ret = FPGA_EXCEPTION;
                        goto out;
                }
                /*allocate memory for PMUs */
                g_fpga_perf = malloc(sizeof(fpga_perf_counter));
                if (!g_fpga_perf) {
                        opae_mutex_unlock(res, &fpga_perf_lock);
                        ret = FPGA_EXCEPTION;
                        goto out;
                }
                if (snprintf(g_fpga_perf->dfl_fme_name, sizeof(g_fpga_perf->dfl_fme_name),
                        "dfl_fme%d", fpga_id) < 0) {
                        OPAE_ERR("snprintf buffer overflow");
                        opae_mutex_unlock(res, &fpga_perf_lock);
                        ret = FPGA_EXCEPTION;
                        goto out;
                }

                if (snprintf(sysfs_perf, sizeof(sysfs_perf),
                        DFL_PERF_SYSFS"/%s", g_fpga_perf->dfl_fme_name) < 0) {
                        OPAE_ERR("snprintf buffer overflow");
                        opae_mutex_unlock(res, &fpga_perf_lock);
                        ret = FPGA_EXCEPTION;
                        goto out;
                }
                if (opae_mutex_unlock(res, &fpga_perf_lock)) {
                        OPAE_MSG("Failed to unlock perf mutex");
                        ret = FPGA_EXCEPTION;
                        goto out;
                }
                if (fpga_Perf_Events(DFL_PERF_SYSFS) != ret) {
                        OPAE_ERR("Failed to parse fpga perf event");
                        goto out;
                }

        } else {
                ret = FPGA_NOT_FOUND;
                goto out;
        }

out:
        globfree(&pglob);
        return ret;
}

fpga_result fpgaPerfCounterStartRecord(void)
{
	uint64_t loop                   = 0;
	uint64_t inner_loop             = 0;
	char buf[DFL_PERF_STR_MAX]      = { 0 };
	struct read_format *rdft        = (struct read_format *) buf;
	int res                         = 0;

	if (opae_mutex_lock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to lock perf mutex");
		return FPGA_EXCEPTION;
	}
	if (ioctl(g_fpga_perf->perf_events[0].fd, PERF_EVENT_IOC_ENABLE,
					PERF_IOC_FLAG_GROUP) == -1) {
		OPAE_ERR("PERF_EVENT_IOC_ENABLE ioctl failed: %s",
							strerror(errno));
		goto out;
	}
	if (read(g_fpga_perf->perf_events[0].fd, rdft, sizeof(buf)) == -1) {
		OPAE_ERR("read fpga perf counter failed");
		goto out;
	}
	for (loop = 0; loop < (uint64_t)rdft->nr; loop++) {
		for (inner_loop = 0; inner_loop < g_fpga_perf->num_perf_events;
								inner_loop++) {
			if (rdft->values[loop].id == g_fpga_perf->perf_events[inner_loop].id)
				g_fpga_perf->perf_events[inner_loop].start_value
						= rdft->values[loop].value;
		}
	}
	if (opae_mutex_unlock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to unlock perf mutex");
		return FPGA_EXCEPTION;
	}
	return FPGA_OK;
out:
	opae_mutex_unlock(res, &fpga_perf_lock);
	return FPGA_EXCEPTION;
}


fpga_result fpgaPerfCounterStopRecord(void)
{
	char buf[DFL_PERF_STR_MAX]      = { 0 };
	uint64_t loop                   = 0;
	uint64_t inner_loop             = 0;
	struct read_format *rdft        = (struct read_format *) buf;
	int res                         = 0;

	if (opae_mutex_lock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to lock perf mutex");
		return FPGA_EXCEPTION;
	}
	if (ioctl(g_fpga_perf->perf_events[0].fd, PERF_EVENT_IOC_DISABLE,
			PERF_IOC_FLAG_GROUP) == -1) {
		OPAE_ERR("PERF_EVENT_IOC_ENABLE ioctl failed: %s",
							strerror(errno));
		goto out;
	}
	if (read(g_fpga_perf->perf_events[0].fd, rdft, sizeof(buf)) == -1) {
		OPAE_ERR("read fpga perf counter failed");
		goto out;
	}
	for (loop = 0; loop < (uint64_t)rdft->nr; loop++) {
		for (inner_loop = 0; inner_loop < g_fpga_perf->num_perf_events;
								inner_loop++) {
			if (rdft->values[loop].id == g_fpga_perf->perf_events[inner_loop].id)
				g_fpga_perf->perf_events[inner_loop].stop_value =
								rdft->values[loop].value;
		}
	}
	if (opae_mutex_unlock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to unlock perf mutex");
		return FPGA_EXCEPTION;
	}
	return FPGA_OK;
out:
	opae_mutex_unlock(res, &fpga_perf_lock);
	return FPGA_EXCEPTION;
}


fpga_result fpgaPerfCounterPrint(FILE *f)
{
	uint64_t loop   = 0;
	int res         = 0;

	if (!f) {
		OPAE_ERR("Invalid input parameters");
		return FPGA_INVALID_PARAM;
	}
	if (opae_mutex_lock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to lock perf mutex");
		return FPGA_EXCEPTION;
	}
	fprintf(f, "\n");
	for (loop = 0; loop < g_fpga_perf->num_perf_events; loop++)
		fprintf(f, "%s\t", g_fpga_perf->perf_events[loop].event_name);
	fprintf(f, "\n");
	for (loop = 0; loop < g_fpga_perf->num_perf_events; loop++) {
		if (!g_fpga_perf->perf_events[loop].config)
			continue;
		fprintf(f, "%ld\t\t", (g_fpga_perf->perf_events[loop].stop_value
				- g_fpga_perf->perf_events[loop].start_value));
	}
	fprintf(f, "\n");
	if (opae_mutex_unlock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to unlock perf mutex");
		return FPGA_EXCEPTION;
	}

	return FPGA_OK;
}


fpga_result fpgaPerfCounterFree(void)
{
	int res = 0;

	if (opae_mutex_lock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to lock perf mutex");
		return FPGA_EXCEPTION;
	}
	if (g_fpga_perf->format_type != NULL) {
		free(g_fpga_perf->format_type);
		g_fpga_perf->format_type = NULL;
	}
	if (g_fpga_perf->perf_events != NULL) {
		free(g_fpga_perf->perf_events);
		g_fpga_perf->perf_events = NULL;
	}
	if (g_fpga_perf != NULL) {
		free(g_fpga_perf);
		g_fpga_perf = NULL;
	}
	if (opae_mutex_unlock(res, &fpga_perf_lock)) {
		OPAE_MSG("Failed to unlock perf mutex");
		return FPGA_EXCEPTION;
	}
	return FPGA_OK;
}
