#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/types.h>
#include "profile.h"

int main() {
    printf("pid: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->pid), offsetof(struct stacktrace_event, pid));
    printf("cpu_id: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->cpu_id), offsetof(struct stacktrace_event, cpu_id));
    printf("timestamp: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->timestamp), offsetof(struct stacktrace_event, timestamp));
    printf("comm: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->comm), offsetof(struct stacktrace_event, comm));
    printf("kstack_sz: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->kstack_sz), offsetof(struct stacktrace_event, kstack_sz));
    printf("ustack_sz: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->ustack_sz), offsetof(struct stacktrace_event, ustack_sz));
    printf("kstack: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->kstack), offsetof(struct stacktrace_event, kstack));
    printf("ustack: size = %lu, offset = %lu\n", sizeof(((struct stacktrace_event *)0)->ustack), offsetof(struct stacktrace_event, ustack));
    return 0;
}