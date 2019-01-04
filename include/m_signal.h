#ifndef __M_SIGNAL_H
#define __M_SIGNAL_H

extern struct mmb mm_signal;


int m_signal_preinit(void *m);
int m_signal_deinit( void *m);
void m_signal_handler(int signo);

#endif
