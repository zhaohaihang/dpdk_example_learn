/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation
 */

#include <time.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_keepalive.h>

#include "shm.h"

struct rte_keepalive_shm *rte_keepalive_shm_create(void)
{
	int fd;
	int idx_core;
	struct rte_keepalive_shm *ka_shm;

	/* If any existing object is not unlinked, it makes it all too easy
	 * for clients to end up with stale shared memory blocks when
	 * restarted. Unlinking makes sure subsequent shm_open by clients
	 * will get the new block mapped below.
	 */
	if (shm_unlink(RTE_KEEPALIVE_SHM_NAME) == -1 && errno != ENOENT) // 解除已有的共享内存对象
		printf("Warning: Error unlinking stale %s (%s)\n",
			RTE_KEEPALIVE_SHM_NAME, strerror(errno));

	fd = shm_open(RTE_KEEPALIVE_SHM_NAME,
		O_CREAT | O_TRUNC | O_RDWR, 0666); // 创建共享内存对象
	if (fd < 0)
		RTE_LOG(INFO, EAL,
			"Failed to open %s as SHM (%s)\n",
			RTE_KEEPALIVE_SHM_NAME,
			strerror(errno));
	else if (ftruncate(fd, sizeof(struct rte_keepalive_shm)) != 0) // 调整共享内存对象的大小
		RTE_LOG(INFO, EAL,
			"Failed to resize SHM (%s)\n", strerror(errno));
	else {
		ka_shm = (struct rte_keepalive_shm *) mmap(
			0, sizeof(struct rte_keepalive_shm),
			PROT_READ | PROT_WRITE,	MAP_SHARED, fd, 0);  //使用mmap函数将共享内存对象映射到进程的地址空间，
		close(fd);
		if (ka_shm == MAP_FAILED)
			RTE_LOG(INFO, EAL,
				"Failed to mmap SHM (%s)\n", strerror(errno));
		else {
			memset(ka_shm, 0, sizeof(struct rte_keepalive_shm)); // 初始化共享内存对象

			/* Initialize the semaphores for IPC/SHM use */
			if (sem_init(&ka_shm->core_died, 1, 0) != 0) { //初始化信号量ka_shm->core_died，用于进程间同步.core_die的初始值为0，
				RTE_LOG(INFO, EAL,
					"Failed to setup SHM semaphore (%s)\n",
					strerror(errno));
				munmap(ka_shm,
					sizeof(struct rte_keepalive_shm));
				return NULL;
			}

			/* Set all cores to 'not present' */
			for (idx_core = 0;
					idx_core < RTE_KEEPALIVE_MAXCORES;
					idx_core++) {  // 将每个核心的状态设置为RTE_KA_STATE_UNUSED，并将core_last_seen_times设置为0
				ka_shm->core_state[idx_core] =
					RTE_KA_STATE_UNUSED;
				ka_shm->core_last_seen_times[idx_core] = 0;
			}

			return ka_shm;
		}
	}
return NULL;
}

void rte_keepalive_relayed_state(struct rte_keepalive_shm *shm,
	const int id_core, const enum rte_keepalive_state core_state,
	__rte_unused uint64_t last_alive)
{
	int count;

	shm->core_state[id_core] = core_state; //更新共享内存中对应核心ID的状态。
	shm->core_last_seen_times[id_core] = last_alive; // 更新共享内存中对应核心ID的最后活动时间。

	if (core_state == RTE_KEEPALIVE_SHM_DEAD) {
		/* Since core has died, also signal ka_agent.
		 *
		 * Limit number of times semaphore can be incremented, in case
		 * ka_agent is not active.
		 */
		if (sem_getvalue(&shm->core_died, &count) == -1) { //函数获取shm->core_died信号量的当前值，并存储在count变量中
			RTE_LOG(INFO, EAL, "Semaphore check failed(%s)\n",
				strerror(errno));
			return;
		}
		if (count > 1) // 如果信号量的当前值大于1，则直接返回。这样可以避免在ka_agent不活跃的情况下多次触发核心死亡的信号。
			return;

		if (sem_post(&shm->core_died) != 0)  // 使用sem_post函数增加shm->core_died信号量的值，以通知ka_agent核心已经死亡。如果增加失败，则记录一条日志。
			RTE_LOG(INFO, EAL,
				"Failed to increment semaphore (%s)\n",
				strerror(errno));
	}
}

void rte_keepalive_shm_cleanup(struct rte_keepalive_shm *ka_shm)
{
	if (shm_unlink(RTE_KEEPALIVE_SHM_NAME) == -1 && errno != ENOENT)
		printf("Warning: Error unlinking  %s (%s)\n",
			RTE_KEEPALIVE_SHM_NAME, strerror(errno));

	if (ka_shm && munmap(ka_shm, sizeof(struct rte_keepalive_shm)) != 0)
		printf("Warning: munmap() failed\n");
}
