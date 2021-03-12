/*
 *  ion.c
 *
 * Memory Allocator functions for ion
 *
 *   Copyright 2011 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#define LOG_TAG "ion"

//#include <cutils/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <ion/ion.h>

#define ALOGE(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)

int ion_open()
{
        int fd = open("/dev/ion", O_RDWR);
        if (fd < 0)
                ALOGE("open /dev/ion failed!\n");
        return fd;
}

int ion_close(int fd)
{
        return close(fd);
}

static int ion_ioctl(int fd, int req, void *arg)
{
        int ret = ioctl(fd, req, arg);
        if (ret < 0) {
                ALOGE("ioctl %x failed with code %d: %s\n", req,
                       ret, strerror(errno));
                return -errno;
        }
        return ret;
}

int ion_alloc(int fd, size_t len, size_t align, unsigned int heap_mask,
              unsigned int flags, ion_handle_t *handle)
{
        int ret;
        struct ion_allocation_data data = {
                .len = len,
                .flags = flags,
                .heap_id_mask = heap_mask
        };

        ret = ion_ioctl(fd, ION_IOC_ALLOC, &data);
        if (ret < 0)
                return ret;
        *handle = data.fd;
        return ret;
}

int ion_free(int fd, ion_handle_t handle)
{
        return close(handle);
}

int ion_map(int fd, ion_handle_t handle, size_t length, int prot,
            int flags, off_t offset, unsigned char **ptr, int *map_fd)
{
        *ptr = mmap(NULL, length, prot, flags, handle, offset);
        if (*ptr == MAP_FAILED) {
                ALOGE("mmap failed: %s\n", strerror(errno));
                return -errno;
        }
        *map_fd = handle;
        return 0;
}

int ion_share(int fd, ion_handle_t handle, int* share_fd)
{
        *share_fd = handle;
        return 0;
}

int ion_query_heap_cnt(int fd, int* cnt)
{
    int ret;
    struct ion_heap_query query;
    memset(&query, 0, sizeof(query));
    ret = ion_ioctl(fd, ION_IOC_HEAP_QUERY, &query);
    if (ret < 0) return ret;
    *cnt = query.cnt;
    return ret;
}

int ion_query_get_heaps(int fd, int cnt, struct ion_heap_data* buffers) {
    int ret;
    struct ion_heap_query query = {
        .cnt = cnt, .heaps = (uintptr_t)buffers,
    };
    ret = ion_ioctl(fd, ION_IOC_HEAP_QUERY, &query);
    return ret;
}







