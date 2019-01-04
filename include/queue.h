#ifndef __QUEUE_H
#define __QUEUE_H

typedef struct queue   
{  
    void **pBase;  
    int front;
    int rear; 
    int maxsize;
	volatile int cnt;
}QUEUE,*PQUEUE;  

#define	isFullQueue(Q)	((Q)->front==((Q)->rear+1)&((Q)->maxsize-1))
#define isEmptyQueue(Q)	((Q)->front==(Q)->rear)


static inline int Enqueue(PQUEUE Q, void *val)  
{  
    //if(isFullQueue(Q))  
    if(Q->cnt==Q->maxsize)
        return MM_FAIL;  
    else  
    {  
        Q->pBase[Q->rear]=val;  
        Q->rear=(Q->rear+1)&(Q->maxsize-1);  
		Q->cnt++;
		mb();
        return MM_SUCCESS;  
    }  
} 

static inline void *Dequeue(PQUEUE Q)  
{  
	void *p;

   // if(isEmptyQueue(Q))  
   if(!Q->cnt)
    {  
        return NULL;  
    }  
    else  
    {  
        p=Q->pBase[Q->front];  
        Q->front=(Q->front+1)&(Q->maxsize-1);  
		Q->cnt--;
        return p;  
    }  
}  

struct fifo {
	volatile unsigned write;     /**< Next position to be written*/
	volatile unsigned read;      /**< Next position to be read */
	unsigned len;                /**< Circular buffer length */
	unsigned elem_size; 		 /**< Pointer size - for 32/64 bit OS */
	void * volatile buffer[0];   /**< The buffer contains mbuf pointers */
};

static inline unsigned
fifo_put(struct fifo *fifo, void **data, unsigned num)
{
	unsigned i = 0;
	unsigned fifo_write = fifo->write;
	unsigned fifo_read = fifo->read;
	unsigned new_write = fifo_write;

	for (i = 0; i < num; i++) {
		new_write = (new_write + 1) & (fifo->len - 1);

		if (new_write == fifo_read)
			break;
		fifo->buffer[fifo_write] = data[i];
		fifo_write = new_write;
	}
	fifo->write = fifo_write;

	return i;
}

static inline unsigned
fifo_get(struct fifo *fifo, void **data, unsigned num)
{
	unsigned i = 0;
	unsigned new_read = fifo->read;
	unsigned fifo_write = fifo->write;

	for (i = 0; i < num; i++) {
		if (new_read == fifo_write)
			break;

		data[i] = fifo->buffer[new_read];
		new_read = (new_read + 1) & (fifo->len - 1);
	}
	fifo->read = new_read;

	return i;
}

static inline unsigned
fifo_count(struct fifo *fifo)
{
	return (fifo->len + fifo->write - fifo->read) & ( fifo->len - 1);
}

static inline unsigned
fifo_free_count(struct fifo *fifo)
{
	return (fifo->read - fifo->write - 1) & (fifo->len - 1);
}

static inline void
fifo_init(struct fifo *fifo, unsigned size,unsigned cell_size)
{
	fifo->write = 0;
	fifo->read = 0;
	fifo->len = size;
	fifo->elem_size= cell_size;
}


#endif
