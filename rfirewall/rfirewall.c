#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>

#include <conn/tcpconn.h>
#include <conn/conn.h>
#include <bpf/bpf-skeleton.h> // generated by build

static int
incr_rlimit_memlock()
{
	struct rlimit lim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &lim);
}

static int 
libbpf_print_fn(enum libbpf_print_level lvl, const char *fmt, va_list args) 
{
	if (lvl == LIBBPF_DEBUG) {
		return 0;
	}

	return vfprintf(stderr, fmt, args);
}

volatile sig_atomic_t exiting = 0;

static void
termination_handler(int sig) 
{
	(void)sig;
	exiting = 1;
}

int 
main(void) 
{
	struct combined_bpf_lib *obj = NULL;
	struct sigaction sa;
	int err;

	// signal handling for Ctrl+C
	// https://www.gnu.org/software/libc/manual/html_node/Sigaction-Function-Example.html
	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; // auto restarts interrupted syscalls
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		fprintf(stderr, "Error with sigaction()'%d', '%s'",
			errno, strerror(errno));
		return 1;
	}
	
	err = incr_rlimit_memlock();
	if (err == -1) {
		fprintf(stderr, "Error increasing RLIMIT_MEMLOCK '%d', '%s'",
			errno, strerror(errno));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn); 

	obj = combined_bpf_lib__open_and_load();
	if (obj == NULL) {
		fprintf(stderr, "Error opening and loading 'combined_bpf_lib *obj' '%d', '%s'",
			errno, strerror(errno));
		goto cleanup;	
	}

	err = combined_bpf_lib__attach(obj);
	if (err) {
		fprintf(stderr, "Error attaching skeleton '%d', '%s'",
			errno, strerror(errno));
		goto cleanup;	
	}

	printf("... Press Ctrl+C to stop.\n");
	print_events(bpf_map__fd(obj->maps.events));
	printf("\nExiting...\n");
	
cleanup:
	combined_bpf_lib__destroy(obj);
	return -err;
}

