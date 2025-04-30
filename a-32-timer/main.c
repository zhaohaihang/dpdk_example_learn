/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>

#define TIMER_RESOLUTION_CYCLES 20000000ULL /* around 10ms at 2 Ghz */

static struct rte_timer timer0;
static struct rte_timer timer1;

/* timer0 callback */
static void
timer0_cb(__attribute__((unused)) struct rte_timer *tim,
	  __attribute__((unused)) void *arg)
{
	static unsigned counter = 0;
	unsigned lcore_id = rte_lcore_id();

	printf("%s() on lcore %u\n", __func__, lcore_id); // __func__ 通过宏编译实现，表示当前的函数名。

	/* this timer is automatically reloaded until we decide to
	 * stop it, when counter reaches 20. */
	if ((counter ++) == 20) //第一个计时器（timer0）的回调仅显示一条消息，直到全局计数器达到20（20秒后）。在这种情况下，使用rte_timer_stop（）函数停止计时器。
		rte_timer_stop(tim);
}

/* timer1 callback */
static void
timer1_cb(__attribute__((unused)) struct rte_timer *tim,
	  __attribute__((unused)) void *arg)
{
	unsigned lcore_id = rte_lcore_id();
	uint64_t hz;

	printf("%s() on lcore %u\n", __func__, lcore_id);

	/* reload it on another lcore */
	hz = rte_get_timer_hz();
	lcore_id = rte_get_next_lcore(lcore_id, 0, 1);
	rte_timer_reset(tim, hz/3, SINGLE, lcore_id, timer1_cb, NULL); //第二个计时器（timer1）的回调显示一条消息，并使用rte_timer_reset（）函数在下一个lcore上重新加载计时器：
}

static __attribute__((noreturn)) int
lcore_mainloop(__attribute__((unused)) void *arg)
{
	uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
	unsigned lcore_id;

	lcore_id = rte_lcore_id();
	printf("Starting mainloop on core %u\n", lcore_id);

	while (1) {
		/*
		 * Call the timer handler on each core: as we don't
		 * need a very precise timer, so only call
		 * rte_timer_manage() every ~10ms (at 2Ghz). In a real
		 * application, this will enhance performances as
		 * reading the HPET timer is not efficient.
		 */
		//正如注释中所解释的，最好使用TSC寄存器（因为它是每核寄存器）来检查是否必须调用rte_timer_manage（）函数。在此示例中，定时器的分辨率为10毫秒。
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();  
			//管理计时器列表并执行回调函数。
			//必须从 EAL 线程的主循环中定期调用此函数。它会浏览待处理的定时器列表，并运行所有过期的定时器。
			//计时器的精度取决于这个函数的调用频率。然而，函数被调用得越频繁，它就会使用更多的CPU资源。
			prev_tsc = cur_tsc;
		}
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint64_t hz;
	unsigned lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	/* init RTE timer library */
	rte_timer_subsystem_init(); //初始化定时器子系统。

	/* init timer structures */
	rte_timer_init(&timer0); // 在使用定时器之前，必须先初始化
	rte_timer_init(&timer1);

	/* load timer0, every second, on master lcore, reloaded automatically */
	hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	//第一个定时器（timer0）加载到主lcore上，每秒到期一次。由于提供了PERIODIC标志，定时器子系统会自动重新加载定时器。回调函数是timer0_cb（）。
	rte_timer_reset(&timer0, hz, PERIODICAL, lcore_id, timer0_cb, NULL); 
	
	/* load timer1, every second/3, on next lcore, reloaded manually */
	//第二个定时器（timer1）每333毫秒在下一个可用的lcore上加载一次。SINGLE标志表示定时器只到期一次，如果需要，必须手动重新加载。回调函数是timer1_cb（）。
	lcore_id = rte_get_next_lcore(lcore_id, 0, 1);
	rte_timer_reset(&timer1, hz/3, SINGLE, lcore_id, timer1_cb, NULL);

	/* call lcore_mainloop() on every slave lcore */1
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_mainloop, NULL, lcore_id);
	}

	/* call it on master lcore too */
	(void) lcore_mainloop(NULL);

	return 0;
}

//定时器使用流程：
//1.rte_timer_subsystem_init
//2.rte_timer_init
// rte_timer_reset
// rte_timer_stop
// rte_timer_manage