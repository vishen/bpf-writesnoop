package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
)

import "C"

var source = `
#include <linux/sched.h> 		// task_struct
#include <linux/tracepoint.h> 	// tracepoint__*__*

struct data_t {
    u64 id;
	u32 ppid;
    u32 pid;
    u32 tid;
    char comm[16];
	char output[255];
};

BPF_PERF_OUTPUT(events);

// args is from /sys/kernel/debug/tracing/events/syscalls/sys_write_enter/format
int do_trace(struct tracepoint__syscalls__sys_enter_write *args){

	struct data_t data = {};
	struct task_struct *task;

	data.id = bpf_get_current_pid_tgid();
    data.pid = data.id >> 32; // PID is higher part

	task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0 as the real_parent->tgid.
    data.ppid = task->real_parent->tgid;

    if (data.pid == $$PID || data.ppid == $$PID) {
		// Do nothing
    } else {
		return 0;
	}

    data.tid = data.id; // Cast and get the lower part

	bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.output, sizeof(data.output), (void *)args->buf);

	events.perf_submit(args, &data, sizeof(data));

	return 0;
};
`

// NOTE: This needs to match the exact fields and ordering
// as is in the bpf programs for the 'data_t' struct.
type event struct {
	Id      uint64
	Ppid    uint32
	Pid     uint32
	Tid     uint32
	Command [16]byte
	Output  [255]byte
}

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Printf("requires exactly one argument; a process 'pid' to filter on.\n")
		return
	}

	pid := flag.Args()[0]
	// Check that the pid argument is an integer.
	if _, err := strconv.Atoi(pid); err != nil {
		log.Fatalf("pid %q is not an integer: %v", pid, err)
	}
	// TODO(vishen): check that the pid exists?

	source = strings.Replace(source, "$$PID", pid, -1)
	m := bcc.NewModule(source, []string{})
	defer m.Close()

	// The function here can be any function defined in the BPF source code.
	tracepoint, err := m.LoadTracepoint("do_trace")
	if err != nil {
		log.Fatalf("unable to load tracepoint: %v", err)
	}

	// This has to be an existing tracepoint.
	if err := m.AttachTracepoint("syscalls:sys_enter_write", tracepoint); err != nil {
		log.Fatalf("unable to attach tracepoint: %v", err)
	}

	// These need to be initialised for the BPF program to load and run.
	table := bcc.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel)
	if err != nil {
		log.Fatal("unable to init perf map: %v\n", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var e event
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
			if err != nil {
				fmt.Printf("failed to decode received data '%s': %s\n", data, err)
				continue
			}
			comm := (*C.char)(unsafe.Pointer(&e.Command))
			output := (*C.char)(unsafe.Pointer(&e.Output))
			fmt.Printf("%q (%d,%d) OUT >> %q\n", C.GoString(comm), e.Pid, e.Ppid, C.GoString(output))
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()

}
