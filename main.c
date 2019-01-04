#include "all.h"

int
main_loop(__attribute__((unused)) void *dummy)
{	
//	RUNNING_LOG_ERROR("fffff %d -> %p\n",rte_lcore_id(),lcore[rte_lcore_id()].run);
	if (NULL != lcore[rte_lcore_id()].run)
	{
		lcore[rte_lcore_id()].run();
	}
}


int main(int argc, char** argv)
{
	int i;
	char argv0_buf[512];

	strcpy(argv0_buf,argv[0]);
	me.param.argv[0]=argv0_buf;

	init();

	/* Launch per-lcore function on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}	

	return 0;
}

