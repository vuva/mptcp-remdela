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
struct redsched_sock_data {
	/* The skb or NULL */
	struct sk_buff *skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 skb_end_seq;
};

/* Struct to store the data of the control block */
struct redsched_cb_data {
	/* The next subflow where a skb should be sent or NULL */
	struct tcp_sock *next_subflow;
};

/* Returns the socket data from a given subflow socket */
static struct redsched_sock_data *redsched_get_sock_data(struct tcp_sock *tp)
{
	return (struct redsched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

/* Returns the control block data from a given meta socket */
static struct redsched_cb_data *redsched_get_cb_data(struct tcp_sock *tp)
{
	return (struct redsched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static bool redsched_get_active_valid_sks(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	int active_valid_sks = 0;

	MPTCP_LOG("redsched_get_active_valid_sks\n");
	mptcp_for_each_sk(mpcb, sk) {
		if (subflow_is_active((struct tcp_sock *)sk) &&
		    !mptcp_is_def_unavailable(sk))
			active_valid_sks++;
	}

	if (active_valid_sks) {
		MPTCP_LOG("\tredsched_get_active_valid_sks returning active_valid_sks = TRUE\n");
	} else {
		MPTCP_LOG("\tredsched_get_active_valid_sks returning active_valid_sks = FALSE\n");
	}
	return active_valid_sks;
}

static bool redsched_use_subflow(struct sock *meta_sk,
				 int active_valid_sks,
				 struct tcp_sock *tp,
				 struct sk_buff *skb)
{
	MPTCP_LOG("redsched_use_subflow\n");

	if (!skb || !mptcp_is_available((struct sock *)tp, skb, false)) {
		MPTCP_LOG("\tredsched_use_subflow returning FALSE because !mptcp_is_available\n");
		return false;
	}

	if (TCP_SKB_CB(skb)->path_mask != 0) {
		MPTCP_LOG("\tredsched_use_subflow returning subflow_is_active(tp)\n");
		return subflow_is_active(tp);
	}

	if (TCP_SKB_CB(skb)->path_mask == 0) {
		if (active_valid_sks == -1)
			active_valid_sks = redsched_get_active_valid_sks(meta_sk);

		if (subflow_is_backup(tp) && active_valid_sks > 0) {
			MPTCP_LOG("\tredsched_use_subflow returning FALSE because (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return false;
		} else {
			MPTCP_LOG("\tredsched_use_subflow returning TRUE because NOT (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return true;
		}
	}

	return false;
}

static struct sock *redundant_get_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct redsched_cb_data *cb_data = redsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct sock *sk;
	struct tcp_sock *tp;

	MPTCP_LOG("redundant_get_subflow\n");

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
static void redsched_correct_skb_pointers(struct sock *meta_sk,
					  struct redsched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	MPTCP_LOG("redsched_correct_skb_pointers\n");

	if (sk_data->skb && !after(sk_data->skb_end_seq, meta_tp->snd_una)) {
		sk_data->skb = NULL;
		MPTCP_LOG("\tredsched_correct_skb_pointers setting sk_data->skb = NULL\n");
	}
}

/* Returns the next skb from the queue */
static struct sk_buff *redundant_next_skb_from_queue(struct sk_buff_head *queue,
						     struct sk_buff *previous,
						     struct sock *meta_sk)
{
	MPTCP_LOG("redundant_next_skb_from_queue\n");
	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\treturning NULL because skb_queue_empty()\n");
		return NULL;
	}

	if (!previous) {
		MPTCP_LOG("\treturning skb_peek(queue)\n");
		return skb_peek(queue);
	}

	if (skb_queue_is_last(queue, previous)) {
		MPTCP_LOG("\treturning NULL because skb_queue_is_last()\n");
		return NULL;
	}

	/* sk_data->skb stores the last scheduled packet for this subflow.
	 * If sk_data->skb was scheduled but not sent (e.g., due to nagle),
	 * we have to schedule it again.
	 *
	 * For the redundant scheduler, there are two cases:
	 * 1. sk_data->skb was not sent on another subflow:
	 *    we have to schedule it again to ensure that we do not
	 *    skip this packet.
	 * 2. sk_data->skb was already sent on another subflow:
	 *    with regard to the redundant semantic, we have to
	 *    schedule it again. However, we keep it simple and ignore it,
	 *    as it was already sent by another subflow.
	 *    This might be changed in the future.
	 *
	 * For case 1, send_head is equal previous, as only a single
	 * packet can be skipped.
	 */
	if (tcp_send_head(meta_sk) == previous) {
		MPTCP_LOG("\treturning tcp_send_head(meta_sk)\n");
		return tcp_send_head(meta_sk);
	}

	MPTCP_LOG("\treturning skb_queue_next(queue, previous)\n");
	return skb_queue_next(queue, previous);
}

static struct sk_buff *redundant_next_segment(struct sock *meta_sk,
					      int *reinject,
					      struct sock **subsk,
					      unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct redsched_cb_data *cb_data = redsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int active_valid_sks = -1;

	MPTCP_LOG("redundant_next_segment\n");

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
	    skb_queue_empty(&meta_sk->sk_write_queue)) {
		/* Nothing to send */
		MPTCP_LOG("\tredundant_next_segment return NULL because skb_queue_empty()\n");
		return NULL;
	}

	/* First try reinjections */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk) {
			MPTCP_LOG("\tredundant_next_segment return NULL because (!*subsk)\n");
			return NULL;
		}
		*reinject = 1;
		MPTCP_LOG("\tredundant_next_segment return reinject sk_buff %p and sock %p\n", skb, *subsk);
		return skb;
	}

	/* Then try indistinctly redundant and normal skbs */

	if (!first_tp)
		first_tp = mpcb->connection_list;

	/* still NULL (no subflow in connection_list?) */
	if (!first_tp) {
		MPTCP_LOG("\tredundant_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}

	tp = first_tp;

	*reinject = 0;
	active_valid_sks = redsched_get_active_valid_sks(meta_sk);
	do {
		struct redsched_sock_data *sk_data;

		/* Correct the skb pointers of the current subflow */
		sk_data = redsched_get_sock_data(tp);
		redsched_correct_skb_pointers(meta_sk, sk_data);

		skb = redundant_next_skb_from_queue(&meta_sk->sk_write_queue,
						    sk_data->skb, meta_sk);
		if (skb && redsched_use_subflow(meta_sk, active_valid_sks, tp,
						skb)) {
			sk_data->skb = skb;
			sk_data->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			cb_data->next_subflow = tp->mptcp->next;
			*subsk = (struct sock *)tp;

			if (TCP_SKB_CB(skb)->path_mask)
				*reinject = -1;
			MPTCP_LOG("\tredundant_next_segment return sk_buff %p and sock %p\n", skb, *subsk);
			return skb;
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	MPTCP_LOG("\tredundant_next_segment return NULL (end of function)\n");
	return NULL;
}

static void redundant_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct redsched_cb_data *cb_data = redsched_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	 * the pointer
	 */
	if (cb_data->next_subflow == tp)
		cb_data->next_subflow = tp->mptcp->next;
}

static struct mptcp_sched_ops mptcp_sched_redundant = {
	.get_subflow = redundant_get_subflow,
	.next_segment = redundant_next_segment,
	.release = redundant_release,
	.name = "redundant",
	.owner = THIS_MODULE,
};

static int __init redundant_register(void)
{
	MPTCP_LOG("redundant_register\n");
	BUILD_BUG_ON(sizeof(struct redsched_sock_data) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct redsched_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_redundant))
		return -1;

	return 0;
}

static void redundant_unregister(void)
{
	MPTCP_LOG("redundant_unregister\n");
	mptcp_unregister_scheduler(&mptcp_sched_redundant);
}

module_init(redundant_register);
module_exit(redundant_unregister);

MODULE_AUTHOR("Tobias Erbshaeusser, Alexander Froemmgen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("REDUNDANT MPTCP");
MODULE_VERSION("0.90");
