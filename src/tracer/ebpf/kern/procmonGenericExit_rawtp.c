/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "procmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "procmonEBPF_maps.h"

SEC("raw_tracepoint/sys_exit")
__attribute__((flatten))
int genericRawExit(struct bpf_our_raw_tracepoint_args *ctx)
{

    {BPF_PRINTK("sys_exit\n");}

    return 0;
}
