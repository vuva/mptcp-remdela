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
 *  This is the tagalong redundant scheduler.  It is supposed to send all packets
 *  redundantly, but each flow pays attention to how many packets behind sk_send_head
 *  it falls.  If it falls too far behind, a subflow will skip sending some redundant
 *  packets to catch up, or "tag along".
 */

#include <linux/module.h>
#include <net/mptcp.h>

//#define MPTCP_DEBUG
#ifdef MPTCP_DEBUG
#define MPTCP_LOG(...) pr_info(__VA_ARGS__)
#else
#define MPTCP_LOG(...)
#endif
//#define MPTCP_TRACE_ON
#ifdef MPTCP_TRACE_ON
#define MPTCP_TRACE(...) pr_info(__VA_ARGS__)
#else
#define MPTCP_TRACE(...)
#endif


/* Struct to store the data of a single subflow */
struct tagalongsched_sock_data {
	/* The skb or NULL */
	struct sk_buff *skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 skb_end_seq;
};

/* Struct to store the data of the control block */
struct tagalongsched_cb_data {
	/* The next subflow where a skb should be sent or NULL */
	struct tcp_sock *next_subflow;
};

/* Returns the socket data from a given subflow socket */
static struct tagalongsched_sock_data *tagalongsched_get_sock_data(struct tcp_sock *tp)
{
	return (struct tagalongsched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

/* Returns the control block data from a given meta socket */
static struct tagalongsched_cb_data *tagalongsched_get_cb_data(struct tcp_sock *tp)
{
	return (struct tagalongsched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static bool tagalongsched_get_active_valid_sks(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	int active_valid_sks = 0;

	MPTCP_LOG("tagalongsched_get_active_valid_sks\n");
	mptcp_for_each_sk(mpcb, sk) {
		if (subflow_is_active((struct tcp_sock *)sk) &&
		    !mptcp_is_def_unavailable(sk))
			active_valid_sks++;
	}

	if (active_valid_sks) {
		MPTCP_LOG("\ttagalongsched_get_active_valid_sks returning active_valid_sks = TRUE\n");
	} else {
		MPTCP_LOG("\ttagalongsched_get_active_valid_sks returning active_valid_sks = FALSE\n");
	}
	return active_valid_sks;
}

static bool tagalongsched_use_subflow(struct sock *meta_sk,
				 int active_valid_sks,
				 struct tcp_sock *tp,
				 struct sk_buff *skb)
{
	MPTCP_LOG("tagalongsched_use_subflow\n");

	if (!skb || !mptcp_is_available((struct sock *)tp, skb, false)) {
		MPTCP_LOG("\ttagalongsched_use_subflow returning FALSE because !mptcp_is_available\n");
		return false;
	}

	if (TCP_SKB_CB(skb)->path_mask != 0) {
		MPTCP_LOG("\ttagalongsched_use_subflow returning subflow_is_active(tp)\n");
		return subflow_is_active(tp);
	}

	if (TCP_SKB_CB(skb)->path_mask == 0) {
		if (active_valid_sks == -1)
			active_valid_sks = tagalongsched_get_active_valid_sks(meta_sk);

		if (subflow_is_backup(tp) && active_valid_sks > 0) {
			MPTCP_LOG("\ttagalongsched_use_subflow returning FALSE because (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return false;
		} else {
			MPTCP_LOG("\ttagalongsched_use_subflow returning TRUE because NOT (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return true;
		}
	}

	return false;
}

static struct sock *tagalong_get_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct tagalongsched_cb_data *cb_data = tagalongsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct sock *sk;
	struct tcp_sock *tp;

	MPTCP_LOG("tagalong_get_subflow\n");

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
			MPTCP_LOG("\treturning sock %p\n", tp);
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
static void tagalongsched_correct_skb_pointers(struct sock *meta_sk,
					  struct tagalongsched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	MPTCP_LOG("tagalongsched_correct_skb_pointers\n");

	if (sk_data->skb && !after(sk_data->skb_end_seq, meta_tp->snd_una)) {
		sk_data->skb = NULL;
		MPTCP_LOG("\ttagalongsched_correct_skb_pointers setting sk_data->skb = NULL\n");
	}
}

/* Compute the number of packets between previous and the current sk_send_head,
 * or, if sksend_head is . */
static int tagalong_steps_behind(struct sk_buff_head *queue,
								struct sk_buff *previous,
								struct sock *meta_sk)
{
	struct sk_buff *send_head = tcp_send_head(meta_sk);
	struct sk_buff *send_tail = skb_peek_tail(queue);

	MPTCP_LOG("\ttagalong_steps_behind\n");
	MPTCP_LOG("\t\tsend_head=%p  send_tail=%p\n",send_head,send_tail);

	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\t\ttagalong_steps_behind returning -1 because skb_queue_empty()\n");
		return -1;
	}

	/* If send_head is null, every segment in the queue has been sent.
	 * Use send_tail as the reference point for computing lag. */
	if (send_head == NULL) {
		//MPTCP_LOG("\t\ttagalong_steps_behind returning -1 because send_head is NULL\n");
		//return -1;
		MPTCP_LOG("\t\ttagalong_steps_behind: send_head is NULL.  Using send_tail for computing lag\n");
		//send_head = send_tail;
	}

	if (previous != NULL) {
		/* count how many steps we can advance previous until it
		 * reaches either send_head or send_tail */
		int steps = 0;
		while (previous != send_head && previous != send_tail) {
			MPTCP_LOG("\t\ttagalong_steps_behind advancing a step...\t%p\n", previous);
			steps ++;
			previous = previous->next;
		}
		MPTCP_LOG("\t\ttagalong_steps_behind finally at\t%p\n", previous);
		if (send_head == NULL || previous == send_head) {
			MPTCP_LOG("\ttagalong_steps_behind returning %d\n",steps);
			return steps;
		}
		MPTCP_LOG("\ttagalong_steps_behind returning 0 because we are ahead of send_head\n");
		return 0;
	}

	MPTCP_LOG("\ttagalong_steps_behind returning -1 because previous = NULL\n");
	return -2;
}


/* return the skb pointer advanced n steps in the queue */
static struct sk_buff *tagalong_advance_skb(struct sk_buff *skb, int num_steps)
{
	int i;
	for (i=0; i<num_steps; i++) {
		skb = skb->next;
	}
	return skb;
}


/* Returns the next skb from the queue */
/*
 * skb = tagalong_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *tagalong_next_skb_from_queue(struct sk_buff_head *queue,
						     struct sk_buff *previous,
						     struct sock *meta_sk,
							 bool *send_head_again)
{
	int lag = 0;
	u32 MAX_LAG = sysctl_mptcp_maxlag;
	struct sk_buff *send_head = tcp_send_head(meta_sk);
	struct sk_buff *skb = NULL;
	u32 i;
	*send_head_again = false;

	/*
	 * For tagalong we only send redundant packets when there
	 * are no new unsent packet waiting.
	 */
	MPTCP_LOG("tagalong_next_skb_from_queue\n");
	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\treturning NULL because skb_queue_empty()\n");
		return NULL;
	}

	if (previous != NULL) {

		MPTCP_LOG("\t\tprevious != NULL\n");

		/* check if this subflow is has already sent the tail of the queue */
		if (skb_queue_is_last(queue, previous)) {
			MPTCP_LOG("\t\treturning NULL because previous!=NULL and skb_queue_is_last()\n");
			return NULL;
		}

		/* if we are not at the tail, check how far back from the send_head we are */
		lag = tagalong_steps_behind(queue, previous, meta_sk);

		/* If lag==0 then previous==send_head and we need to try sending send_head again */
		if (previous == tcp_send_head(meta_sk)) {
			MPTCP_LOG("\t\treturning previous because (previous == tcp_send_head(meta_sk))  %p  %p\n",previous,tcp_send_head(meta_sk));
			*send_head_again = true;
			return previous;
		}

		/* if necessary, catch up with the leading subflow */
		if ((lag > 0) && (lag > MAX_LAG)) {
			MPTCP_LOG("\t\treturning previous advanced by %d steps\n", (lag - MAX_LAG));
			return tagalong_advance_skb(previous, lag-MAX_LAG);
		}

		/* otherwise just send the next thing in our queue */
		MPTCP_LOG("\t\treturning previous->next\n");
		return previous->next;
	}

	/* previous is null.
	 * This means that the last segment we sent on this subflow has been ACKed.
	 * The proper behavior for tagalong is to start at send_head (or send_tail if send_head is null)
	 * and count backwards to MAX_LAG steps.
	 */
	MPTCP_LOG("\t\tprevious == NULL\n");
	skb = send_head;
	if (send_head == NULL) {
		skb = skb_peek_tail(queue);
	}

	/* the queue is empty.  This should have been caught above. */
	if (! skb) {
		return NULL;
	}

	/* Backtrack by the appropriate possible lag and re-send one of them. */
	i = 0;
	while (i < MAX_LAG && skb->prev != (const struct sk_buff *) queue) {
		i++;
		skb = skb->prev;
	}
	MPTCP_LOG("\t\treturning backtracked %d steps from tcp_send_head(meta_sk)\n",i);
	return skb;
}


/*
 * tagalong scheduler is supposed to behave like oppredundant when MAX_LAG=0
 * and like redundant when MAX_LAG is very large.  This function help verify
 * this behavior by taking the skb's returned by the different schedulers
 * and, if they are different, logging the full queue.
 */
static void dump_queue(struct sk_buff *skb, struct sk_buff *skb2, struct sk_buff_head *queue, struct sock *meta_sk, char* sched_name) {
	struct sk_buff *skbi;

	if (skb != skb2) {
		pr_info("tagalong != redundant\t\t%p\t%p\t%p\n",skb,skb2,queue);
		skbi = skb_peek_tail(&meta_sk->sk_write_queue);
		while (skbi != (struct sk_buff *)queue) {
			if (skbi == tcp_send_head(meta_sk)) {
				pr_info("%p\t%u\t send_head\n",skbi,TCP_SKB_CB(skbi)->seq);
			} else {
				pr_info("%p\t%u\n",skbi,TCP_SKB_CB(skbi)->seq);
			}
			if (skbi == skb) {
				pr_info("\t\t tagalong\n");
			}
			if (skbi == skb2) {
				pr_info("\t\t %s\n",sched_name);
			}
			skbi = skbi->prev;
		}
	}
}


static struct sk_buff *tagalong_next_segment(struct sock *meta_sk,
					      int *reinject,
					      struct sock **subsk,
					      unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct tagalongsched_cb_data *cb_data = tagalongsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int active_valid_sks = -1;

	MPTCP_LOG("tagalong_next_segment\n");
	MPTCP_LOG("\tstarting with first_tp=%p\n",first_tp);

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
	    skb_queue_empty(&meta_sk->sk_write_queue)) {
		/* Nothing to send */
		MPTCP_LOG("\ttagalong_next_segment return NULL because skb_queue_empty()\n");
		return NULL;
	}

	/* First try reinjections */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk) {
			MPTCP_LOG("\ttagalong_next_segment return NULL because (!*subsk)\n");
			return NULL;
		}
		*reinject = 1;
		MPTCP_LOG("\ttagalong_next_segment return reinject sk_buff %p and sock %p\n", skb, *subsk);
		return skb;
	}

	/* Then try indistinctly redundant and normal skbs */

	if (!first_tp) {
		first_tp = mpcb->connection_list;
		MPTCP_LOG("\tfirst_tp undefined.  setting first_tp = mpcb->connection_list=%p\n",first_tp);
	}

	/* still NULL (no subflow in connection_list?) */
	if (!first_tp) {
		MPTCP_LOG("\ttagalong_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}

	tp = first_tp;

	*reinject = 0;
	active_valid_sks = tagalongsched_get_active_valid_sks(meta_sk);
	do {
		bool send_head_again = false;
		struct tagalongsched_sock_data *sk_data;
		MPTCP_LOG("\ttagalong_next_segment trying sock %p\n", tp);

		/* Correct the skb pointers of the current subflow */
		sk_data = tagalongsched_get_sock_data(tp);
		tagalongsched_correct_skb_pointers(meta_sk, sk_data);

		/* I find it weird that this does the work to pick the next skb and *then*
		 * checks if the skb can be sent on the subflow.  Shouldn't we just check
		 * the CWND up front before investing any work in this subflow?
		 */

		skb = tagalong_next_skb_from_queue(&meta_sk->sk_write_queue,
						    sk_data->skb, meta_sk, &send_head_again);
		//dump_queue(skb, redundant_next_skb_from_queue(&meta_sk->sk_write_queue,sk_data->skb, meta_sk),
		//					&meta_sk->sk_write_queue, meta_sk, "redundant");

		MPTCP_LOG("\ttagalong_next_segment tagalong_next_skb_from_queue returned %p\n", skb);
		if (skb && tagalongsched_use_subflow(meta_sk, active_valid_sks, tp,
						skb)) {
			if (send_head_again) {
				MPTCP_TRACE("%p\t%p\t%u\t%u\tsend_head again",tp,skb,TCP_SKB_CB(skb)->seq,TCP_SKB_CB(skb)->end_seq);
			} else {
				MPTCP_TRACE("%p\t%p\t%u\t%u",tp,skb,TCP_SKB_CB(skb)->seq,TCP_SKB_CB(skb)->end_seq);
			}
			if (sk_data->skb_end_seq > TCP_SKB_CB(skb)->end_seq) {
				MPTCP_TRACE("\tbackwards in data sequence!\t%u\t%u",sk_data->skb_end_seq, TCP_SKB_CB(skb)->end_seq);
			}

			sk_data->skb = skb;
			sk_data->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			cb_data->next_subflow = tp->mptcp->next;
			MPTCP_LOG("\t\tfirst_tp setting cb_data->next_subflow=%p\n",cb_data->next_subflow);
			*subsk = (struct sock *)tp;

			if (TCP_SKB_CB(skb)->path_mask)
				*reinject = -1;
			MPTCP_LOG("\ttagalong_next_segment return sk_buff %p and sock %p\n", skb, *subsk);
			return skb;
		} else {
			MPTCP_LOG("\ttagalong_next_segment skipping because !skb or !use_subflow");
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	MPTCP_LOG("\ttagalong_next_segment return NULL (end of function)\n");
	return NULL;
}


static void tagalong_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tagalongsched_cb_data *cb_data = tagalongsched_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	 * the pointer
	 */
	if (cb_data->next_subflow == tp)
		cb_data->next_subflow = tp->mptcp->next;
}

static struct mptcp_sched_ops mptcp_sched_tagalong = {
	.get_subflow = tagalong_get_subflow,
	.next_segment = tagalong_next_segment,
	.release = tagalong_release,
	.name = "tagalong",
	.owner = THIS_MODULE,
};

static int __init tagalong_register(void)
{
	MPTCP_LOG("tagalong_register\n");
	BUILD_BUG_ON(sizeof(struct tagalongsched_sock_data) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct tagalongsched_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_tagalong))
		return -1;

	return 0;
}

static void tagalong_unregister(void)
{
	MPTCP_LOG("tagalong_unregister\n");
	mptcp_unregister_scheduler(&mptcp_sched_tagalong);
}

module_init(tagalong_register);
module_exit(tagalong_unregister);

MODULE_AUTHOR("Tobias Erbshaeusser, Alexander Froemmgen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TAGALONG REDUNDANT MPTCP");
MODULE_VERSION("0.90");
