/*
 *	MPTCP Scheduler to reduce latency and jitter.
 *
 *	This scheduler sends all packets redundantly on all available subflows.
 *
 *	Initial Design & Implementation:
 *	Tobias Erbshaeusser <erbshauesser@dvs.tu-darmstadt.de>
 *	Alexander Froemmgen <froemmge@dvs.tu-darmstadt.de>
 *
 *	Initial corrections & modifications:
 *	Christian Pinedo <christian.pinedo@ehu.eus>
 *	Igor Lopez <igor.lopez@ehu.eus>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *  This is the louden redundant scheduler.  It acts like tagalong, but transmits packets
 *  on the reinject queue with first priority on all subflows.  That is, it applies
 *  redundant-style scheduling to the reinject queue.
 */

#include <linux/module.h>
#include <net/mptcp.h>

#define MPTCP_DEBUG
#ifdef MPTCP_DEBUG
#define MPTCP_LOG(...) pr_info(__VA_ARGS__)
#else
#define MPTCP_LOG(...)
#endif

/* Struct to store the data of a single subflow */
struct loudensched_sock_data {
	/* The skb or NULL */
	struct sk_buff *skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 skb_end_seq;

	/* the most recently transmitted skb on the reinject queue, or NULL */
	struct sk_buff *reinject_skb;
	u32 reinject_skb_end_seq;
};

/* Struct to store the data of the control block */
struct loudensched_cb_data {
	/* The next subflow where a skb should be sent or NULL */
	struct tcp_sock *next_subflow;
};

/* Returns the socket data from a given subflow socket */
static struct loudensched_sock_data *loudensched_get_sock_data(struct tcp_sock *tp)
{
	return (struct loudensched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

/* Returns the control block data from a given meta socket */
static struct loudensched_cb_data *loudensched_get_cb_data(struct tcp_sock *tp)
{
	return (struct loudensched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static bool loudensched_get_active_valid_sks(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	int active_valid_sks = 0;

	//MPTCP_LOG("    \tloudensched_get_active_valid_sks\n");
	mptcp_for_each_sk(mpcb, sk) {
		if (subflow_is_active((struct tcp_sock *)sk) &&
		    !mptcp_is_def_unavailable(sk))
			active_valid_sks++;
	}

	//if (active_valid_sks) {
		//MPTCP_LOG("    \t\tloudensched_get_active_valid_sks returning active_valid_sks = TRUE\n");
	//} else {
		//MPTCP_LOG("    \t\tloudensched_get_active_valid_sks returning active_valid_sks = FALSE\n");
	//}
	return active_valid_sks;
}

static bool loudensched_use_subflow(struct sock *meta_sk,
				 int active_valid_sks,
				 struct tcp_sock *tp,
				 struct sk_buff *skb)
{
	MPTCP_LOG("    \tloudensched_use_subflow\n");

	if (!skb || !mptcp_is_available((struct sock *)tp, skb, false)) {
		MPTCP_LOG("    \t\tloudensched_use_subflow returning FALSE because !mptcp_is_available\n");
		return false;
	}

	if (TCP_SKB_CB(skb)->path_mask != 0) {
		MPTCP_LOG("    \t\tloudensched_use_subflow returning subflow_is_active(tp)\n");
		return subflow_is_active(tp);
	}

	if (TCP_SKB_CB(skb)->path_mask == 0) {
		if (active_valid_sks == -1)
			active_valid_sks = loudensched_get_active_valid_sks(meta_sk);

		if (subflow_is_backup(tp) && active_valid_sks > 0) {
			MPTCP_LOG("'t\tloudensched_use_subflow returning FALSE because (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return false;
		} else {
			MPTCP_LOG("    \t\tloudensched_use_subflow returning TRUE because NOT (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return true;
		}
	}

	return false;
}

static struct sock *louden_get_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct loudensched_cb_data *cb_data = loudensched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct sock *sk;
	struct tcp_sock *tp;

	MPTCP_LOG("louden_get_subflow\n");

	/* Answer data_fin on same subflow */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index ==
				mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	if (!first_tp)
		first_tp = mpcb->connection_list;
	tp = first_tp;

	/* still NULL (no subflow in connection_list?) */
	if (!first_tp)
		return NULL;

	/* Search for any subflow to send it */
	do {
		if (mptcp_is_available((struct sock *)tp, skb,
				       zero_wnd_test)) {
			cb_data->next_subflow = tp->mptcp->next;
			MPTCP_LOG("    \treturning sock %p\n", tp);
			return (struct sock *)tp;
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* No space */
	return NULL;
}

/* Corrects the stored skb pointers if they are invalid */
static void loudensched_correct_skb_pointers(struct sock *meta_sk,
					  struct loudensched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	MPTCP_LOG("    \tloudensched_correct_skb_pointers\n");

	/* check if the last packet sent on this subflow has been ACKed already */
	if (sk_data->skb && !after(sk_data->skb_end_seq, meta_tp->snd_una)) {
		sk_data->skb = NULL;
		MPTCP_LOG("    \t\tloudensched_correct_skb_pointers setting sk_data->skb = NULL\n");
	}

	/* check if the last reinject packet sent on this subflow has been ACKed already */
	if (sk_data->reinject_skb && !after(sk_data->reinject_skb_end_seq, meta_tp->snd_una)) {
		sk_data->reinject_skb = NULL;
		MPTCP_LOG("    \t\tloudensched_correct_skb_pointers setting sk_data->reinject_skb = NULL\n");
	}
}

/* Compute the number of packets between previous and the current sk_send_head,
 * or, if sksend_head is . */
static int louden_steps_behind(struct sk_buff_head *queue,
								struct sk_buff *previous,
								struct sock *meta_sk)
{

	struct sk_buff *send_head = tcp_send_head(meta_sk);
	struct sk_buff *send_tail = skb_peek_tail(queue);

	MPTCP_LOG("    \tlouden_steps_behind\n");

	if (skb_queue_empty(queue)) {
		//MPTCP_LOG("    \t\tlouden_steps_behind returning 0 because skb_queue_empty()\n");
		return 0;
	}

	if (previous != NULL) {
		/* count how many steps we can advance previous until it
		 * reaches either send_head or send_tail */
		int steps = 0;
		while (previous != send_head && previous != send_tail) {
			MPTCP_LOG("    \t\tlouden_steps_behind advancing a step...\t%p\n", previous);
			steps ++;
			previous = previous->next;
		}
		//MPTCP_LOG("    \t\tlouden_steps_behind finally at\t%p\n", previous);
		if (previous == send_head) {
			MPTCP_LOG("    \t\tlouden_steps_behind returning %d\n",steps);
			return steps;
		}
		MPTCP_LOG("    \t\tlouden_steps_behind returning 0 because we are ahead of send_head\n");
		return 0;
	}

	MPTCP_LOG("    \t\tlouden_steps_behind returning -1 because previous = NULL\n");
	return -1;
}

/* return the skb pointer advanced n steps in the queue */
static struct sk_buff *louden_advance_skb(struct sk_buff *skb, int num_steps)
{
	int i;
	for (i=0; i<num_steps; i++) {
		skb = skb->next;
	}
	return skb;
}


/* Returns the next skb from the queue */
/*
 * skb = louden_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *louden_next_skb_from_queue(struct sk_buff_head *queue,
						     struct sk_buff *previous,
						     struct sock *meta_sk)
{
	u32 lag = 0;
	u32 MAX_LAG = sysctl_mptcp_maxlag;

	/*
	 * For louden we only send redundant packets when there
	 * are no new unsent packet waiting.
	 */
	MPTCP_LOG("    louden_next_skb_from_queue\n");
	if (skb_queue_empty(queue)) {
		MPTCP_LOG("    \treturning NULL because skb_queue_empty()\n");
		return NULL;
	}

	if (previous != NULL) {

		MPTCP_LOG("    \t\tprevious != NULL\n");

		/* check if this subflow is has already sent the tail of the queue */
		if (skb_queue_is_last(queue, previous)) {
			MPTCP_LOG("    \t\treturning NULL because previous!=NULL and skb_queue_is_last()\n");
			return NULL;
		}

		/* if we are not at the tail, check how far back from the send_head we are */
		lag = louden_steps_behind(queue, previous, meta_sk);

		/* If lag==0 then previous==send_head and we need to try sending send_head again */
		if (lag == 0) {
			MPTCP_LOG("    \t\treturning previous because lag==0  %p  %p\n",previous,tcp_send_head(meta_sk));
			return previous;
		}

		/* if necessary, catch up with the leading subflow */
		if (lag > MAX_LAG) {
			MPTCP_LOG("    \t\treturning previous advanced by %d steps\n", (lag - MAX_LAG));
			return louden_advance_skb(previous, lag-MAX_LAG);
		}

		/* otherwise just send the next thing in our queue */
		MPTCP_LOG("    \t\treturning previous->next\n");
		return previous->next;
	}

	/* previous is null.  If there are unsent packets in the meta queue, send the next one */
	/*
	 * This is questionable.  If the connection is idle, and then several packets arrive,
	 * this will lead to no redundancy at first.  Really we would like to re-send the last
	 * packet sent - not send a new one.  But how can we tell if send_head has been sent on
	 * another subflow or not?
	 * It is also a problem when there are losses on the subflow.  The CWND is small and it ends
	 * up waiting for ACKs.  Then when it's time to send a new packet, previous is null.
	 *
	 * Here's some reasoning:  If previous is null, but send_head->prev is not, then someone
	 * else must have sent send_head->prev.  We can start at send_head->prev and backtrack
	 * for the appropriate lag, knowing that we haven't sent any of the packets in the
	 * current meta queue.
	 */

	MPTCP_LOG("    \t\tprevious == NULL\n");
	if (tcp_send_head(meta_sk) != NULL) {
		u32 i = 0;
		struct sk_buff *skb = tcp_send_head(meta_sk);

		MPTCP_LOG("    \t\ttcp_send_head(meta_sk) != NULL\n");

		if (tcp_send_head(meta_sk)->prev == (const struct sk_buff *) queue) {
			/* There are no un-ACKed packets before the current send_head.
			 * Everything in flight has been ACKed.  Send a new packet.
			 * This case is superflous given the code below.  Should remove it. */
			MPTCP_LOG("    \t\treturning tcp_send_head(meta_sk)\n");
			return tcp_send_head(meta_sk);
		}

		/* There are packets that were sent on another link but not yet ACKed.
		 * Backtrack by the appropriate possible lag and re-send one of them. */
		while (i < MAX_LAG && skb->prev != (const struct sk_buff *) queue) {
			i++;
			skb = skb->prev;
		}
		MPTCP_LOG("    \t\treturning backtracked %d steps from tcp_send_head(meta_sk)\n",i);
		return skb;
	}

	/* If there are no unsent packets, re-send the tail of the queue.
	 * If we get here the tail should actually be null. */
	MPTCP_LOG("    \t\treturning skb_peek_tail(queue)\n");
	return skb_peek_tail(queue);
}


/* Returns the next skb from the queue */
/*
 * skb = louden_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *louden_next_skb_from_reinject_queue(struct sk_buff_head *queue,
						     struct sk_buff *previous,
						     struct sock *meta_sk)
{

	MPTCP_LOG("    louden_next_skb_from_reinject_queue\n");
	if (skb_queue_empty(queue)) {
		MPTCP_LOG("    \treturning NULL because reinject skb_queue_empty()\n");
		return NULL;
	}

	MPTCP_LOG("    \treinject queue not empty!\n");

	if (!previous) {
		MPTCP_LOG("    \t\treturning skb_peek(queue)\n");
		return skb_peek(queue);
	}

	if (skb_queue_is_last(queue, previous)) {
		MPTCP_LOG("    \t\treturning NULL because skb_queue_is_last()\n");
		return NULL;
	}

	if (tcp_send_head(meta_sk) == previous) {
		MPTCP_LOG("    \t\treturning tcp_send_head(meta_sk)\n");
		return tcp_send_head(meta_sk);
	}

	MPTCP_LOG("    \t\treturning skb_queue_next(queue, previous)\n");
	return skb_queue_next(queue, previous);
}



static struct sk_buff *louden_next_segment(struct sock *meta_sk,
					      int *reinject,
					      struct sock **subsk,
					      unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct loudensched_cb_data *cb_data = loudensched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int active_valid_sks = -1;

	MPTCP_LOG("=================== louden_next_segment ===================\n");
	//MPTCP_LOG("    \tstarting with first_tp=%p\n",first_tp);

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
	    skb_queue_empty(&meta_sk->sk_write_queue)) {
		/* Nothing to send */
		MPTCP_LOG("    \tlouden_next_segment return NULL because skb_queue_empty()\n");
		return NULL;
	}

	if (!first_tp) {
		first_tp = mpcb->connection_list;
		//MPTCP_LOG("    \tfirst_tp undefined.  setting first_tp = mpcb->connection_list=%p\n",first_tp);
	}

	/* still NULL (no subflow in connection_list?) */
	if (!first_tp) {
		MPTCP_LOG("    \tlouden_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}

	tp = first_tp;

	/* First try reinjections.
	 * The old way was to grab the next reinject packet, if any, and then
	 * send it on a subflow that is available.  Usually the immediately available
	 * subflow would be the same one the packet was sent on before.
	 * The louden scheduler attempts to send every reinjected packet on /every/
	 * subflow, similar to how the redundant scheduler handles the normal send queue.
	 * */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk) {
			MPTCP_LOG("    \tlouden_next_segment return NULL because (!*subsk)\n");
			return NULL;
		}
		*reinject = 1;
		MPTCP_LOG("    \tlouden_next_segment return reinject sk_buff %p and sock %p\n", skb, *subsk);
		return skb;
	}

	active_valid_sks = loudensched_get_active_valid_sks(meta_sk);
	do {
		struct loudensched_sock_data *sk_data;
		MPTCP_LOG("   ---------- louden_next_segment trying sock %p ----------\n", tp);

		/* Correct the skb pointers of the current subflow */
		sk_data = loudensched_get_sock_data(tp);
		loudensched_correct_skb_pointers(meta_sk, sk_data);

		/* first check if there is anything we can reinject on this subflow */
		skb = louden_next_skb_from_reinject_queue(&mpcb->reinject_queue, sk_data->reinject_skb, meta_sk);
		if (skb) {
			MPTCP_LOG("    \t\tlouden_next_segment louden_next_skb_from_REINJECT_queue returned %p\n", skb);
			*reinject = 1;
		} else {
			skb = louden_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
			MPTCP_LOG("    \t\tlouden_next_segment louden_next_skb_from_queue returned %p\n", skb);
			*reinject = 0;
		}

		if (skb && loudensched_use_subflow(meta_sk, active_valid_sks, tp, skb)) {
			if (*reinject) {
				sk_data->reinject_skb = skb;
				sk_data->reinject_skb_end_seq = TCP_SKB_CB(skb)->end_seq;

			} else {
				sk_data->skb = skb;
				sk_data->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			}
			cb_data->next_subflow = tp->mptcp->next;
			//MPTCP_LOG("    \t\tfirst_tp setting cb_data->next_subflow=%p\n",cb_data->next_subflow);
			*subsk = (struct sock *)tp;

			if (!reinject && TCP_SKB_CB(skb)->path_mask)
				*reinject = -1;
			MPTCP_LOG("    \tlouden_next_segment return sk_buff=%p    sock=%p    reinject=%d\n", skb, *subsk, *reinject);
			return skb;
		} else {
			MPTCP_LOG("    \tlouden_next_segment skipping because !skb or !use_subflow");
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	MPTCP_LOG("    \tlouden_next_segment return NULL (end of function)\n");
	return NULL;
}

static void louden_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct loudensched_cb_data *cb_data = loudensched_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	 * the pointer
	 */
	if (cb_data->next_subflow == tp)
		cb_data->next_subflow = tp->mptcp->next;
}

static struct mptcp_sched_ops mptcp_sched_louden = {
	.get_subflow = louden_get_subflow,
	.next_segment = louden_next_segment,
	.release = louden_release,
	.name = "louden",
	.owner = THIS_MODULE,
};

static int __init louden_register(void)
{
	MPTCP_LOG("louden_register\n");
	BUILD_BUG_ON(sizeof(struct loudensched_sock_data) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct loudensched_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_louden))
		return -1;

	return 0;
}

static void louden_unregister(void)
{
	MPTCP_LOG("louden_unregister\n");
	mptcp_unregister_scheduler(&mptcp_sched_louden);
}

module_init(louden_register);
module_exit(louden_unregister);

MODULE_AUTHOR("Tobias Erbshaeusser, Alexander Froemmgen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LOUDEN REDUNDANT MPTCP");
MODULE_VERSION("0.90");
