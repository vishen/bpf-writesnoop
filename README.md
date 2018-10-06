# BPF Writesnoop

Use BPF to trace linux tracepoints for the `write` syscall. This can be used to
watch any `write` syscalls a process or a child process makes. This requires
to be run as root.

## Running

```
$ cat t.go
package main

import (
        "fmt"
        "time"
)

func main() {
        for i := 0; ; i++ {
                fmt.Printf("%d) hello, go\n", i)
                time.Sleep(time.Second)
        }
}
$ go run t.go

# Attach to the `go run t.go` process
$ sudo ./bpf-writesnoop 2182
"t" (2260,2182) OUT >> "25) hello, go\n"
"t" (2260,2182) OUT >> "26) hello, go\n"
"t" (2260,2182) OUT >> "27) hello, go\n"
"t" (2260,2182) OUT >> "28) hello, go\n"
"t" (2260,2182) OUT >> "29) hello, go\n"
"t" (2260,2182) OUT >> "30) hello, go\n"
```


## Linux tracepoint

This uses the `syscalls:sys_enter_write` tracepoint to watch for any `write` syscalls.
Because we only care about what is being written, we can watch the sys_enter tracepoints.

```
$ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format

name: sys_enter_write
ID: 648
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:const char * buf; offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))
```

In this case we only care about the `buf` argument, which is the text being written by
the `write` syscall.

The tracepoint argument structure is in the format `struct tracepoint__<type>__<name>`, for
`syscalls:sys_enter_write` it would be `struct tracepoint__syscalls__sys_enter_write`.

## Using Gobpf

Gobpf doesn't provide the same "magic" functionality that `bcc` provides, such as automagically
loading and attaching tracepoints, kprobes and uprobes for you, so you always need to manually
load and attach the functions you want to trace.

Loading and attaching the BPF does not mean that the functions are now being traced, you
need to also create a new table `bcc.NewTable` and create a perf map `bcc.InitPerfMap`,
once these have been created and initialised the BPF functions will now be loaded and
we start getting events from the traced functions.

## Resources

```
- https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
- https://github.com/iovisor/bpf-docs
- https://github.com/iovisor/bpf-docs/blob/master/bpf_helpers.rst
```
