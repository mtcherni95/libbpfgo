//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>  

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

struct proc_info {  
    int pid;  
    char comm[100];
};



struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);

} events SEC(".maps");

long ringbuffer_flags = 0;

int kprobe__sys_execve(struct pt_regs *ctx) {

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    struct proc_info *process; // Reserve space on the ringbuffer for the sample process = bpf_ringbuf_reserve(&events, sizeof(proc_info), ringbuffer_flags);

    if (!process) {

        return 0;
    }

    process->pid = tgid;

    bpf_get_current_comm(&process->comm, 100); bpf_ringbuf_submit(process, ringbuffer_flags);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";