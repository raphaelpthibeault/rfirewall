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
#include <assert.h>
#include <pthread.h>

#include <conn/tcpconn.h>
#include <conn/conn.h>
#include <bpf/bpf-skeleton.h> // generated by build
#include <conn/packets.h>


/* TODO rfirewall_daemon.c ? */

struct thread_info
{
	pthread_t thread_id; /* ID returned by pthread_create() */	
	int thread_num; /* Application-defined thread # */
	void *arg;	
	int exiting;
	pthread_mutex_t lock;
};

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
	if (lvl == LIBBPF_DEBUG) 
		return 0;

	return vfprintf(stderr, fmt, args);
}

volatile sig_atomic_t exiting = 0;

static void
termination_handler(int sig) 
{
	(void)sig;
	exiting = 1;
}

static inline __attribute__((always_inline)) int
thread_should_exit(struct thread_info *tinfo)
{
	int status, res;

	status = pthread_mutex_lock(&tinfo->lock);
	assert(status == 0);

	res = tinfo->exiting;

	status = pthread_mutex_unlock(&tinfo->lock);
	assert(status == 0);

	return res;
}


static void *
probe_thread_fn(void *arg)
{
	struct thread_info *tinfo = arg;
	printf("Thread %d\n", tinfo->thread_num);

	int ringbuf_fd = *((int *)tinfo->arg);
	if (conn_init(ringbuf_fd) != 0)
	{
		fprintf(stderr, "conn_init() failure");
		goto done;
	}

	while (!thread_should_exit(tinfo))
	{
		if (conn_poll() != 0)
		{
			fprintf(stderr, "conn_poll() failure");
			goto done;
		}
	}

done:
	conn_deinit();
	return NULL;	
}

static void *
filter_thread_fn(void *arg)
{
	struct thread_info *tinfo = arg;
	int ret;
	printf("Thread %d\n", tinfo->thread_num);

	ret = filter_init();
	if (ret != 0)
	{
		fprintf(stderr, "filter_init() failure");
	}

	printf("Filtering packets...\n");

	while (!thread_should_exit(tinfo))
	{
		if (filter_step() != 0)
		{
			fprintf(stderr, "filter_step() failure");
			goto done;
		}
	}

done:
	filter_deinit();
	return NULL;
}

int 
main(void) 
{
	struct combined_bpf_lib *obj = NULL;
	struct sigaction sa;
	int err = 0;
	int ret;
	pthread_attr_t attr;
	struct thread_info *tinfo = NULL;;
	size_t num_threads = 2;


	/* ----- Signal Handling ----- */
	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; // auto restarts interrupted syscalls
	if (sigaction(SIGINT, &sa, NULL) == -1) 
	{
		fprintf(stderr, "Error with sigaction()'%d', '%s'",
			errno, strerror(errno));
		return 1;
	}
	
	err = incr_rlimit_memlock();
	if (err == -1) 
	{
		fprintf(stderr, "Error increasing RLIMIT_MEMLOCK '%d', '%s'",
			errno, strerror(errno));
		return 1;
	}

	/* ----- BPF Setup ----- */
	libbpf_set_print(libbpf_print_fn); 

	obj = combined_bpf_lib__open_and_load();
	if (obj == NULL) 
	{
		fprintf(stderr, "Error opening and loading 'combined_bpf_lib *obj' '%d', '%s'",
			errno, strerror(errno));
		goto cleanup;	
	}

	err = combined_bpf_lib__attach(obj);
	if (err) 
	{
		fprintf(stderr, "Error attaching skeleton '%d', '%s'",
			errno, strerror(errno));
		goto cleanup;	
	}

	/* ----- Threading Setup ----- */
	ret = pthread_attr_init(&attr);
	if (ret != 0)
	{
		perror("pthread_attr_init() failure");
		exit(EXIT_FAILURE);
	}

	tinfo = calloc(num_threads, sizeof(*tinfo));
	if (tinfo == NULL)
	{
		fprintf(stderr, "calloc failed");
		goto cleanup;
	}

	for (size_t tnum = 0; tnum < num_threads; ++tnum)
	{
    if (pthread_mutex_init(&tinfo[tnum].lock, NULL) != 0) 
		{
			fprintf(stderr, "pthread_mutex_init() failed on tinfo[%lu]", tnum);
			goto cleanup;
    }
	}

	int ringbuf_fd = bpf_map__fd(obj->maps.events);
	tinfo[0].thread_num = 1;
	tinfo[0].arg = (void *)&ringbuf_fd;
	tinfo[0].exiting = 0;
	ret = pthread_create(&tinfo[0].thread_id, &attr, &probe_thread_fn, &tinfo[0]);
	if (ret != 0)
	{
		fprintf(stderr, "pthread_create() failure (probe_thread)");
		goto cleanup;
	}

	tinfo[1].thread_num = 2;
	tinfo[1].exiting = 0;
	ret = pthread_create(&tinfo[1].thread_id, &attr, &filter_thread_fn, &tinfo[1]);
	if (ret != 0)
	{
		fprintf(stderr, "pthread_create() failure (filter_thread)");
		goto cleanup;
	}

	ret = pthread_attr_destroy(&attr);	
	if (ret != 0)
	{
		perror("pthread_attr_destroy");
		exit(EXIT_FAILURE);
	}

	/* threads have been created, wait on Ctrl+C to stop program */
	printf("... Press Ctrl+C to stop.\n");

	while (!exiting)
	{
		sleep(1);	
	}// <-- Ctrl+c has been pressed

	printf("\nExiting...\n");

	for (size_t tnum = 0; tnum < num_threads; ++tnum)
	{
		pthread_mutex_lock(&tinfo[tnum].lock);
		tinfo[tnum].exiting = 1;
		pthread_mutex_unlock(&tinfo[tnum].lock);
	}

	/* block wait for the threads to exit */
	for (size_t tnum = 0; tnum < num_threads; ++tnum)
	{
		ret = pthread_join(tinfo[tnum].thread_id, NULL); // assume no return value for now
		if (ret != 0)
		{
			perror("pthread_join() failure");
			exit(EXIT_FAILURE);
		}
	}


cleanup:
	if (obj != NULL)
		combined_bpf_lib__destroy(obj);

	if (tinfo != NULL)
	{
		for (size_t i = 0; i < num_threads; i++) 
		{
			pthread_mutex_destroy(&tinfo[i].lock);
		}

		free(tinfo);
	}

	return -err;
}


