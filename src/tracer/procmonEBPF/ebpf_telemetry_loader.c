/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/


#include "ebpf_telemetry_loader.h"
#include "../procmon_defs.h"
#include "syscalls.h"

#define MAP_PAGE_SIZE (16 * 1024)
#define DEBUGFS "/sys/kernel/debug/tracing/"

#define KERN_4_15_4_16_OBJ "procmonEBPFkern4.15-4.16.o"
#define KERN_4_17_5_1_OBJ  "procmonEBPFkern4.17-5.1.o"
#define KERN_5_2_OBJ       "procmonEBPFkern5.2.o"
#define KERN_5_3__OBJ      "procmonEBPFkern5.3-.o"

#ifndef STOPLOOP
    #define STOPLOOP 0
#endif

double             g_bootSecSinceEpoch=1;
extern syscall_names_s    syscall_num_to_name[SYSCALL_MAX+1];

static unsigned int       isTesting = STOPLOOP;

static int                event_map_fd = 0;
static int                config_map_fd = 0;
static struct utsname     uname_s = { 0 };
static struct bpf_object  *bpf_obj = NULL;

static struct bpf_program *bpf_sys_enter_tp[7];
static struct bpf_program *bpf_sys_enter = NULL;
static struct bpf_program *bpf_sys_exit = NULL;

static struct bpf_link    *bpf_sys_enter_tp_link[SYSCALL_MAX+1];
static struct bpf_link    *bpf_sys_exit_tp_link[SYSCALL_MAX+1];
static struct bpf_link    *bpf_sys_enter_link = NULL;
static struct bpf_link    *bpf_sys_exit_link = NULL;

bool                      raw_tracepoints = false;

void ebpf_telemetry_close_all(){
    
    if (!raw_tracepoints) {
        for (int i=0; i<=SYSCALL_MAX; i++) {
            if (bpf_sys_enter_tp_link[i])
                bpf_link__destroy(bpf_sys_enter_tp_link[i]);
            if (bpf_sys_exit_tp_link[i])
                bpf_link__destroy(bpf_sys_exit_tp_link[i]);
        }
    } else {
        bpf_link__destroy(bpf_sys_enter_link);
        bpf_link__destroy(bpf_sys_exit_link);
    }

    bpf_object__close(bpf_obj);
}

unsigned int *find_config_item(config_s *c, char *param)
{
    if (!strcmp(param, "parent"))
        return c->parent;
    else if (!strcmp(param, "pid"))
        return c->pid;
    else if (!strcmp(param, "ppid"))
        return c->ppid;
    else if (!strcmp(param, "auid"))
        return c->auid;
    else if (!strcmp(param, "ses"))
        return c->ses;
    else if (!strcmp(param, "start_time"))
        return c->start_time;
    else if (!strcmp(param, "cred"))
        return c->cred;
    else if (!strcmp(param, "cred_uid"))
        return c->cred_uid;
    else if (!strcmp(param, "cred_gid"))
        return c->cred_gid;
    else if (!strcmp(param, "cred_euid"))
        return c->cred_euid;
    else if (!strcmp(param, "cred_suid"))
        return c->cred_suid;
    else if (!strcmp(param, "cred_fsuid"))
        return c->cred_fsuid;
    else if (!strcmp(param, "cred_egid"))
        return c->cred_egid;
    else if (!strcmp(param, "cred_sgid"))
        return c->cred_sgid;
    else if (!strcmp(param, "cred_fsgid"))
        return c->cred_fsgid;
    else if (!strcmp(param, "tty"))
        return c->tty;
    else if (!strcmp(param, "comm"))
        return c->comm;
    else if (!strcmp(param, "exe_path"))
        return c->exe_path;
    else if (!strcmp(param, "mm_arg_start"))
        return c->mm_arg_start;
    else if (!strcmp(param, "mm_arg_end"))
        return c->mm_arg_end;
    else if (!strcmp(param, "mm_start_code"))
        return c->mm_start_code;
    else if (!strcmp(param, "mm_end_code"))
        return c->mm_end_code;
    else if (!strcmp(param, "pwd_path"))
        return c->pwd_path;
    else if (!strcmp(param, "path_vfsmount"))
        return c->path_vfsmount;
    else if (!strcmp(param, "path_dentry"))
        return c->path_dentry;
    else if (!strcmp(param, "dentry_parent"))
        return c->dentry_parent;
    else if (!strcmp(param, "dentry_name"))
        return c->dentry_name;
    else if (!strcmp(param, "dentry_inode"))
        return c->dentry_inode;
    else if (!strcmp(param, "inode_mode"))
        return c->inode_mode;
    else if (!strcmp(param, "inode_ouid"))
        return c->inode_ouid;
    else if (!strcmp(param, "inode_ogid"))
        return c->inode_ogid;
    else if (!strcmp(param, "mount_mnt"))
        return c->mount_mnt;
    else if (!strcmp(param, "mount_parent"))
        return c->mount_parent;
    else if (!strcmp(param, "mount_mountpoint"))
        return c->mount_mountpoint;
    else if (!strcmp(param, "max_fds"))
        return c->max_fds;
    else if (!strcmp(param, "fd_table"))
        return c->fd_table;
    else if (!strcmp(param, "fd_path"))
        return c->fd_path;
    else return NULL;
}

bool insert_config_offsets(unsigned int *item, char *value)
{
    char *offset = NULL;
    unsigned int i;
    char *inner_strtok = NULL;

    offset = strtok_r(value, " ,", &inner_strtok);
    if (!offset) {
        item[0] = -1;
        return false;
    }

    i = 0;

    while (offset && i < (NUM_REDIRECTS - 1)) {
        item[i] = atoi(offset);
        offset = strtok_r(NULL, " ,", &inner_strtok);
        i++;
    }
    item[i] = DEREF_END;

    return true;
}


bool populate_config_offsets(config_s *c)
{
    FILE *config;
    char *line = NULL;
    size_t len = 0;
    ssize_t read_len;
    char *param = NULL;
    char *value = NULL;
    char *whitespace = NULL;
    unsigned int *item = NULL;
    char *outer_strtok = NULL;

    config = fopen(CONFIG_FILE, "r");
    if (!config)
        return false;

    while ((read_len = getline(&line, &len, config)) >= 0) {
        if (read_len > 0 && line[0] == '#')
            continue;
        whitespace = line;
        while (*whitespace == ' ')
            whitespace++;
        param = strtok_r(whitespace, " =", &outer_strtok);
        if (!param)
            continue;
        value = strtok_r(NULL, "\n", &outer_strtok);
        if (!value)
            continue;
        whitespace = value;
        while (*whitespace == ' ' || *whitespace == '=')
            whitespace++;
        value = whitespace;

        item = find_config_item(c, param);

        if (item)
            insert_config_offsets(item, value);
    }

    free(line);
    fclose(config);

    return true;
}

/*bool populate_active_events(config_s *c, bool* configEvents)
{
    if (!c || !configEvents)
        return false;

    // copy which Sysmon events are active
    memcpy(c->events, configEvents, sizeof(c->events));

    // config which syscalls to report on
    memset(c->active, 0, sizeof(c->active));
    if (configEvents[SYSMONEVENT_CREATE_PROCESS_EVENT_value]) {
        c->active[__NR_execve] = true;
        c->active[__NR_execveat] = true;
    }
    return true;
}*/

int ebpf_telemetry_start(
    bool *configEvents,
    void (*event_cb)(void *ctx, int cpu, void *data, __u32 size),
    void (*events_lost_cb)(void *ctx, int cpu, __u64 lost_cnt),
    void* ctx
    )
{
    unsigned int major = 0, minor = 0;
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    char filename[256];
    char filepath[PATH_MAX];
    struct stat filepath_stat;

    if (uname(&uname_s)){
        fprintf(stderr, "Couldn't find uname, '%s'\n", strerror(errno));
        return 1;
    }

    if (sscanf(uname_s.release, "%u.%u", &major, &minor) == 2){
        fprintf(stderr, "Found Kernel version: %u.%u\n", major, minor);
    }
    else{
        fprintf(stderr, "Couldn't find version\n");
        return 1;
    }    

    // <  4.15, no ebpf support due to no direct r/w access to maps
    // 4.15 - 4.16 - tracepoints
    // 4.17 - 5.1  - raw tracepoints, <4096 instructions, no loops
    // 5.2         - raw tracepoints, <1M instructions, no loops
    // >= 5.3      - raw tracepoints, <1M instructions, loops

    if ((major < 4) || (major == 4 && minor < 15)) {
        fprintf(stderr, "Kernel Version %u.%u not supported\n", major, minor);
        return 1;    
    } else if (major == 4 && minor <= 16) {
        snprintf(filename, sizeof(filename), "%s", KERN_4_15_4_16_OBJ);
        raw_tracepoints = false;
        fprintf(stderr, "Using Tracepoints, sub 4096 instructions, no loops\n");
    } else if ((major == 4) || (major == 5 && minor <= 1)) {
        snprintf(filename, sizeof(filename), "%s", KERN_4_17_5_1_OBJ);
        raw_tracepoints = true;
        fprintf(stderr, "Using Raw Tracepoints, sub 4096 instructions, no loops\n");
    } else if (major == 5 && minor == 2) {
        snprintf(filename, sizeof(filename), "%s", KERN_5_2_OBJ);
        raw_tracepoints = true;
        fprintf(stderr, "Using Raw Tracepoints, sub 1M instructions, no loops\n");
    } else {
        snprintf(filename, sizeof(filename), "%s", KERN_5_3__OBJ);
        raw_tracepoints = true;
        fprintf(stderr, "Using Raw Tracepoints, sub 1M instructions, with loops\n");
    }

    // discover path
    snprintf(filepath, PATH_MAX, "%s", filename);

    fprintf(stderr, "Using filepath %s\n", filepath);

    if (stat(filepath, &filepath_stat) != 0 || !S_ISREG(filepath_stat.st_mode)) {
        snprintf(filepath, PATH_MAX, "%s/%s", SYSMON_EBPF_DIR, filename);
        if (stat(filepath, &filepath_stat) != 0 || !S_ISREG(filepath_stat.st_mode)) {
            snprintf(filepath, PATH_MAX, "%s/%s", SYSMON_INSTALL_DIR, filename);
            if (stat(filepath, &filepath_stat) != 0 || !S_ISREG(filepath_stat.st_mode)) {
                snprintf(filepath, PATH_MAX, "%s/%s/%s", SYSMON_INSTALL_DIR, SYSMON_EBPF_DIR, filename);
                if (stat(filepath, &filepath_stat) != 0 || !S_ISREG(filepath_stat.st_mode)) {
                    printf("Cannot locate EBPF kernel object: %s\n", filename);
                    return 1;
                }
            }
        }
    }

    fprintf(stderr, "Using EBPF object: %s\n", filepath);

    setrlimit(RLIMIT_MEMLOCK, &lim);

    bpf_obj = bpf_object__open(filepath);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "ERROR: failed to open prog: '%s'\n", strerror(errno));
        return 1;
    }

    if (!raw_tracepoints) {
        char program_name[] = "tracepoint/syscalls/sys_enter0";
        unsigned int program_name_len = strlen(program_name);
        for (int n=0; n<7; n++) {
            program_name[program_name_len - 1] = '0' + n;
            if ((bpf_sys_enter_tp[n] = bpf_object__find_program_by_title(bpf_obj, program_name)) == NULL) {
                fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", program_name, strerror(errno));
                break;
            }
            bpf_program__set_type(bpf_sys_enter_tp[n], BPF_PROG_TYPE_TRACEPOINT);
        }
        if ((bpf_sys_exit = bpf_object__find_program_by_title(bpf_obj,"tracepoint/syscalls/sys_exit")) == NULL) {
            fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", program_name, strerror(errno));
        }
        bpf_program__set_type(bpf_sys_exit, BPF_PROG_TYPE_TRACEPOINT);
    } else {
        if (((bpf_sys_enter = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/sys_enter")) != NULL)  &&
                ((bpf_sys_exit  = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/sys_exit")) != NULL)) {
            bpf_program__set_type(bpf_sys_enter, BPF_PROG_TYPE_RAW_TRACEPOINT);
            bpf_program__set_type(bpf_sys_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        } else {
            fprintf(stderr, "ERROR: failed to find program: '%s'\n", strerror(errno));
            return 1;
        }
    }

    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "ERROR: failed to load prog: '%s'\n", strerror(errno));
        return 1;
    }

    event_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "event_map");
    if (event_map_fd <= 0) {
        fprintf(stderr, "ERROR: failed to load event_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    config_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "config_map");
    if (config_map_fd <= 0) {
        fprintf(stderr, "ERROR: failed to load config_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    //populate config
    unsigned int config_entry = 0;
    config_s config;
    config.userland_pid = getpid();
    populate_config_offsets(&config);
    config.bootNsSinceEpoch = g_bootSecSinceEpoch * (1000 * 1000 * 1000);

//    populate_active_events(&config, configEvents);
    config.active[__NR_execve] = true;
    config.active[__NR_execveat] = true;

    if (bpf_map_update_elem(config_map_fd, &config_entry, &config, BPF_ANY)) {
        fprintf(stderr, "ERROR: failed to set config: '%s'\n", strerror(errno));
        return 1;
    }

    if (!raw_tracepoints) {
        for (unsigned int i=0; i<=SYSCALL_MAX; i++) {
            int j;
            memset(bpf_sys_enter_tp_link, 0, sizeof(bpf_sys_enter_tp_link));
            if (config.active[i]) {
                char tracepoint[SYSCALL_NAME_LEN * 2];
                snprintf(tracepoint, SYSCALL_NAME_LEN * 2, "sys_enter_%s", syscall_num_to_name[i].name);
                j = syscall_num_to_name[i].num_args;
                bpf_sys_enter_tp_link[i] = bpf_program__attach_tracepoint(bpf_sys_enter_tp[j], "syscalls", tracepoint);
                if (libbpf_get_error(bpf_sys_enter_tp_link[i]))
                    return 2;
                snprintf(tracepoint, SYSCALL_NAME_LEN * 2, "sys_exit_%s", syscall_num_to_name[i].name);
                bpf_sys_exit_tp_link[i] = bpf_program__attach_tracepoint(bpf_sys_exit, "syscalls", tracepoint);
                if (libbpf_get_error(bpf_sys_exit_tp_link[i]))
                    return 2;
            }
        }
    } else {
        bpf_sys_enter_link = bpf_program__attach_raw_tracepoint(bpf_sys_enter, "sys_enter");
        bpf_sys_exit_link = bpf_program__attach_raw_tracepoint(bpf_sys_exit, "sys_exit");
        
        if ( (libbpf_get_error(bpf_sys_enter_link)) || (libbpf_get_error(bpf_sys_exit_link)) )
            return 2;
    }

    // from Kernel 5.7.1 ex: trace_output_user.c 
    struct perf_buffer_opts pb_opts = {0};
    struct perf_buffer *pb;
    int ret;

    pb_opts.sample_cb = event_cb;
    pb_opts.lost_cb = events_lost_cb;
    pb_opts.ctx = ctx;
    pb = perf_buffer__new(event_map_fd, MAP_PAGE_SIZE, &pb_opts); // param 2 is page_cnt == number of pages to mmap.
    ret = libbpf_get_error(pb);
    if (ret) {
        fprintf(stderr, "ERROR: failed to setup perf_buffer: %d\n", ret);
        return 1;
    }

    fprintf(stderr, "Running...\n");

    int i = 0;
    while ((ret = perf_buffer__poll(pb, 1000)) >= 0 ) {
        if (isTesting){
            if (i++ > STOPLOOP) break;
        }
    }

    ebpf_telemetry_close_all();

    return 0;
}
