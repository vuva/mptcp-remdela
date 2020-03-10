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
 *  This is the opportunistic redundant scheduler, sending packets packets on all subflows
 *  which have not exhausted their congestion window when a packet is scheduled
 *  for the first time.
 */

#include <linux/module.h>
#include <net/mptcp.h>

//#define MPTCP_DEBUG
#ifdef MPTCP_DEBUG
#define MPTCP_LOG(...) pr_info(__VA_ARGS__)
#else
#define MPTCP_LOG(...)
#endif

/* Struct to store the data of a single subflow */
struct oppredsched_sock_data {
	/* The skb or NULL */
	struct sk_buff *skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 skb_end_seq;
};

/* Struct to store the data of the control block */
struct oppredsched_cb_data {
	/* The next subflow where a skb should be sent or NULL */
	struct tcp_sock *next_subflow;
};

/* Returns the socket data from a given subflow socket */
static struct oppredsched_sock_data *oppredsched_get_sock_data(struct tcp_sock *tp)
{
	return (struct oppredsched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

/* Returns the control block data from a given meta socket */
static struct oppredsched_cb_data *oppredsched_get_cb_data(struct tcp_sock *tp)
{
	return (struct oppredsched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static bool oppredsched_get_active_valid_sks(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	int active_valid_sks = 0;

	MPTCP_LOG("oppredsched_get_active_valid_sks\n");
	mptcp_for_each_sk(mpcb, sk) {
		if (subflow_is_active((struct tcp_sock *)sk) &&
		    !mptcp_is_def_unavailable(sk))
			active_valid_sks++;
	}

	if (active_valid_sks) {
		MPTCP_LOG("\toppredsched_get_active_valid_sks returning active_valid_sks = TRUE\n");
	} else {
		MPTCP_LOG("\toppredsched_get_active_valid_sks returning active_valid_sks = FALSE\n");
	}
	return active_valid_sks;
}

static bool oppredsched_use_subflow(struct sock *meta_sk,
				 int active_valid_sks,
				 struct tcp_sock *tp,
				 struct sk_buff *skb)
{
	MPTCP_LOG("oppredsched_use_subflow\n");

	if (!skb || !mptcp_is_available((struct sock *)tp, skb, false)) {
		MPTCP_LOG("\toppredsched_use_subflow returning FALSE because !mptcp_is_available\n");
		return false;
	}

	if (TCP_SKB_CB(skb)->path_mask != 0) {
		MPTCP_LOG("\toppredsched_use_subflow returning subflow_is_active(tp)\n");
		return subflow_is_active(tp);
	}

	if (TCP_SKB_CB(skb)->path_mask == 0) {
		if (active_valid_sks == -1)
			active_valid_sks = oppredsched_get_active_valid_sks(meta_sk);

		if (subflow_is_backup(tp) && active_valid_sks > 0) {
			MPTCP_LOG("\toppredsched_use_subflow returning FALSE because (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return false;
		} else {
			MPTCP_LOG("\toppredsched_use_subflow returning TRUE because NOT (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return true;
		}
	}

	return false;
}

static struct sock *oppredundant_get_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct oppredsched_cb_data *cb_data = oppredsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct sock *sk;
	struct tcp_sock *tp;

	MPTCP_LOG("oppredundant_get_subflow\n");

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
static void oppredsched_correct_skb_pointers(struct sock *meta_sk,
					  struct oppredsched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	MPTCP_LOG("oppredsched_correct_skb_pointers\n");

	if (sk_data->skb && !after(sk_data->skb_end_seq, meta_tp->snd_una)) {
		sk_data->skb = NULL;
		MPTCP_LOG("\toppredsched_correct_skb_pointers setting sk_data->skb = NULL\n");
	}
}

/* Returns the next skb from the queue */
/*
 * skb = oppredundant_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *oppredundant_next_skb_from_queue(struct sk_buff_head *queue,
						     struct sk_buff *previous,
						     struct sock *meta_sk)
{
	/*
	 * For oppredundant we only send redundant packets when there
	 * are no new unsent packet waiting.
	 */
	MPTCP_LOG("oppredundant_next_skb_from_queue\n");
	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\treturning NULL because skb_queue_empty()\n");
		return NULL;
	}

	/* check if this subflow is has already sent the tail of the queue */
	if (previous != NULL) {
		if (skb_queue_is_last(queue, previous)) {
			MPTCP_LOG("\treturning NULL because previous!=NULL and skb_queue_is_last()\n");
			return NULL;
		}
	}

	/* whether or not previous is null, if there are unsent packets, send the next one */
	if (tcp_send_head(meta_sk) != NULL) {
		MPTCP_LOG("\treturning tcp_send_head(meta_sk)\n");
		return tcp_send_head(meta_sk);
	}

	/* If there are no unsent packets, re-send the tail of the queue */
	MPTCP_LOG("\treturning skb_peek_tail(queue)\n");
	return skb_peek_tail(queue);
}

static struct sk_buff *oppredundant_next_segment(struct sock *meta_sk,
					      int *reinject,
					      struct sock **subsk,
					      unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct oppredsched_cb_data *cb_data = oppredsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int active_valid_sks = -1;

	MPTCP_LOG("oppredundant_next_segment\n");

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
	    skb_queue_empty(&meta_sk->sk_write_queue)) {
		/* Nothing to send */
		MPTCP_LOG("\toppredundant_next_segment return NULL because skb_queue_empty()\n");
		return NULL;
	}

	/* First try reinjections */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk) {
			MPTCP_LOG("\toppredundant_next_segment return NULL because (!*subsk)\n");
			return NULL;
		}
		*reinject = 1;
		MPTCP_LOG("\toppredundant_next_segment return reinject sk_buff %p and sock %p\n", skb, *subsk);
		return skb;
	}

	/* Then try indistinctly redundant and normal skbs */

	if (!first_tp)
		first_tp = mpcb->connection_list;

	/* still NULL (no subflow in connection_list?) */
	if (!first_tp) {
		MPTCP_LOG("\toppredundant_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}

	tp = first_tp;

	*reinject = 0;
	active_valid_sks = oppredsched_get_active_valid_sks(meta_sk);
	do {
		struct oppredsched_sock_data *sk_data;
		MPTCP_LOG("\toppredundant_next_segment trying sock %p\n", tp);

		/* Correct the skb pointers of the current subflow */
		sk_data = oppredsched_get_sock_data(tp);
		oppredsched_correct_skb_pointers(meta_sk, sk_data);

		/* I find it weird that this does the work to pick the next skb and *then*
		 * checks if the skb can be sent on the subflow.  Shouldn't we just check
		 * the CWND up front before investing any work in this subflow?
		 */

		skb = oppredundant_next_skb_from_queue(&meta_sk->sk_write_queue,
						    sk_data->skb, meta_sk);
		if (skb && oppredsched_use_subflow(meta_sk, active_valid_sks, tp,
						skb)) {
			sk_data->skb = skb;
			sk_data->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			cb_data->next_subflow = tp->mptcp->next;
			*subsk = (struct sock *)tp;

			if (TCP_SKB_CB(skb)->path_mask)
				*reinject = -1;
			MPTCP_LOG("\toppredundant_next_segment return sk_buff %p and sock %p\n", skb, *subsk);
			return skb;
		} else {
			MPTCP_LOG("\toppredundant_next_segment skipping because !skb or !use_subflow");
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	MPTCP_LOG("\toppredundant_next_segment return NULL (end of function)\n");
	return NULL;
}

static void oppredundant_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct oppredsched_cb_data *cb_data = oppredsched_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	 * the pointer
	 */
	if (cb_data->next_subflow == tp)
		cb_data->next_subflow = tp->mptcp->next;
}

static struct mptcp_sched_ops mptcp_sched_oppredundant = {
	.get_subflow = oppredundant_get_subflow,
	.next_segment = oppredundant_next_segment,
	.release = oppredundant_release,
	.name = "oppredundant",
	.owner = THIS_MODULE,
};

static int __init oppredundant_register(void)
{
	MPTCP_LOG("oppredundant_register\n");
	BUILD_BUG_ON(sizeof(struct oppredsched_sock_data) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct oppredsched_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_oppredundant))
		return -1;

	return 0;
}

static void oppredundant_unregister(void)
{
	MPTCP_LOG("oppredundant_unregister\n");
	mptcp_unregister_scheduler(&mptcp_sched_oppredundant);
}

module_init(oppredundant_register);
module_exit(oppredundant_unregister);

MODULE_AUTHOR("Tobias Erbshaeusser, Alexander Froemmgen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OPPORTUNISTIC REDUNDANT MPTCP");
MODULE_VERSION("0.90");
