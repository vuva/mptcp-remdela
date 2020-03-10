/*
 * mptcp_lazytail.c
 *
 *  Created on: Mar 19, 2018
 *      Author: brenton
 */


/*
 *	MPTCP Scheduler to reduce latency and jitter.
 *
 *
 *  This is the lazytail redundant scheduler.  It is a hybrid of tagalong and redundant.
 *  Each subflow maintains two pointers into the ring of un-ACKed packets.
 *  The (monkey's) head behaves like tagalong, skipping ahead to keep up with the
 *  fastest flow.  The monkey's tail stays behind pointing to the oldest un-ACKed packet
 *  that has not been sent on this subflow.
 */

#include <linux/module.h>
#include <net/mptcp.h>

//#define MPTCP_DEBUG
#ifdef MPTCP_DEBUG
#define MPTCP_LOG(...) pr_info(__VA_ARGS__)
#else
#define MPTCP_LOG(...)
#endif
//#define MPTCP_DEBUG2
#ifdef MPTCP_DEBUG2
#define MPTCP_LOG2(...) pr_info(__VA_ARGS__)
#else
#define MPTCP_LOG2(...)
#endif

//#define TAIL_SERVICE_INTERVAL 2

/* Struct to store the data of a single subflow
 * This is larger than 16 bytes and required increasing MPTCP_SCHED_SIZE in mptcp.h.
 */
struct lazytailsched_sock_data {
	/* The skb (or NULL) that tries to keep up with the leading flow */
	struct sk_buff *monkeyhead_skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 monkeyhead_skb_end_seq;

	/* The skb (or NULL) that tracks the oldest un-ACKed packet not sent on this flow */
	struct sk_buff *lazytail_skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 lazytail_skb_end_seq;

	/* This flag indicates whether the head and tail are in sync or not. */
	bool lazytail_synced;

	/* When the head and tail are not synced, the keeps track of the last place the head jumped to. */
	u32 monkeyhead_last_jump_seq;

	/* Keep track of the number of monkeyhead packets sent since the last lazytail service */
	u32 lazytail_service_counter;

	bool recover_mode;
	bool recover_sent;
	u32 leading_subsk_rtt;
};

/* Struct to store the data of the control block */
struct lazytailsched_cb_data {
	/* The next subflow where a skb should be sent or NULL */
	struct tcp_sock *next_subflow;
};

/* Returns the socket data from a given subflow socket */
static struct lazytailsched_sock_data *lazytailsched_get_sock_data(struct tcp_sock *tp)
{
	return (struct lazytailsched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

/* Returns the control block data from a given meta socket */
static struct lazytailsched_cb_data *lazytailsched_get_cb_data(struct tcp_sock *tp)
{
	return (struct lazytailsched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static bool lazytailsched_get_active_valid_sks(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	int active_valid_sks = 0;

	//MPTCP_LOG("lazytailsched_get_active_valid_sks\n");
	mptcp_for_each_sk(mpcb, sk) {
		if (subflow_is_active((struct tcp_sock *)sk) &&
		    !mptcp_is_def_unavailable(sk))
			active_valid_sks++;
	}

	//if (active_valid_sks) {
	//	MPTCP_LOG("\tlazytailsched_get_active_valid_sks returning active_valid_sks = TRUE\n");
	//} else {
	//	MPTCP_LOG("\tlazytailsched_get_active_valid_sks returning active_valid_sks = FALSE\n");
	//}
	return active_valid_sks;
}

static bool lazytailsched_use_subflow(struct sock *meta_sk,
				 int active_valid_sks,
				 struct tcp_sock *tp,
				 struct sk_buff *skb)
{
	//MPTCP_LOG("\tlazytailsched_use_subflow\n");

	if (!skb || !mptcp_is_available((struct sock *)tp, skb, false)) {
		//MPTCP_LOG("\t\tlazytailsched_use_subflow returning FALSE because !mptcp_is_available\n");
		return false;
	}

	if (TCP_SKB_CB(skb)->path_mask != 0) {
		//MPTCP_LOG("\t\tlazytailsched_use_subflow returning subflow_is_active(tp)\n");
		return subflow_is_active(tp);
	}

	if (TCP_SKB_CB(skb)->path_mask == 0) {
		if (active_valid_sks == -1)
			active_valid_sks = lazytailsched_get_active_valid_sks(meta_sk);

		if (subflow_is_backup(tp) && active_valid_sks > 0) {
			//MPTCP_LOG("\t\tlazytailsched_use_subflow returning FALSE because (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return false;
		} else {
			//MPTCP_LOG("\t\tlazytailsched_use_subflow returning TRUE because NOT (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return true;
		}
	}

	return false;
}

static struct sock *lazytail_get_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct lazytailsched_cb_data *cb_data = lazytailsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct sock *sk;
	struct tcp_sock *tp;

	MPTCP_LOG("lazytail_get_subflow\n");

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
static void lazytailsched_correct_skb_pointers(struct sock *meta_sk,
					  struct lazytailsched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	//MPTCP_LOG("\tlazytailsched_correct_skb_pointers\n");

	if (sk_data->monkeyhead_skb && !after(sk_data->monkeyhead_skb_end_seq, meta_tp->snd_una)) {
		sk_data->monkeyhead_skb = NULL;
		//MPTCP_LOG("\t\tlazytailsched_correct_skb_pointers setting sk_data->monkeyhead_skb = NULL\n");
	}
	if (! sk_data->lazytail_synced) {
		//MPTCP_LOG("\t\tlazytailsched_correct_skb_pointers: !sk_data->lazytail_synced\n");
		if (sk_data->lazytail_skb && !after(sk_data->lazytail_skb_end_seq, meta_tp->snd_una)) {
			sk_data->lazytail_skb = NULL;
			//MPTCP_LOG("\t\tlazytailsched_correct_skb_pointers setting sk_data->lazytail_skb = NULL\n");
		}
	}
	if (!sk_data->lazytail_synced && !after(sk_data->monkeyhead_skb_end_seq, meta_tp->snd_una) && !after(sk_data->lazytail_skb_end_seq, meta_tp->snd_una)) {
		MPTCP_LOG2("\t\t\t\t head and tail overtaken by ACKs \t%u\t%u\t%u\n",sk_data->lazytail_skb_end_seq, sk_data->monkeyhead_skb_end_seq, meta_tp->snd_una);
	}
}

/* Compute the number of packets between previous and the current sk_send_head.
 * If previous->next == send_head, then this will return 1.  This is the normal
 * state of things, and indicates the subflow is not lagging at all.
 * If previous is at, or ahead of, send_head it will return 0.  This
 * should actually never happen.
 *  */
static int lazytail_steps_behind(struct sk_buff_head *queue,
								struct sk_buff *previous,
								struct sock *meta_sk)
{
	struct sk_buff *send_head = tcp_send_head(meta_sk);
	struct sk_buff *send_tail = skb_peek_tail(queue);

	MPTCP_LOG("\tlazytail_steps_behind\n");
	MPTCP_LOG("\t\tsend_head=%p  send_tail=%p\n",send_head,send_tail);

	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\t\tlazytail_steps_behind returning -1 because skb_queue_empty()\n");
		return -1;
	}

	/* If send_head is null, every segment in the queue has been sent.
	 * Use send_tail as the reference point for computing lag. */
	if (send_head == NULL) {
		//MPTCP_LOG("\t\tlazytail_steps_behind returning -1 because send_head is NULL\n");
		//return -1;
		MPTCP_LOG("\t\tlazytail_steps_behind: send_head is NULL.  Using send_tail for computing lag\n");
		//send_head = send_tail;
	}

	if (previous != NULL) {
		/* count how many steps we can advance previous until it
		 * reaches either send_head or send_tail */
		int steps = 0;
		while (previous != send_head && previous != send_tail) {
			MPTCP_LOG("\t\tlazytail_steps_behind advancing a step...\t%p\n", previous);
			steps ++;
			previous = previous->next;
		}
		MPTCP_LOG("\t\tlazytail_steps_behind finally at\t%p\n", previous);
		if (send_head == NULL || previous == send_head) {
			MPTCP_LOG("\tlazytail_steps_behind returning %d\n",steps);
			return steps;
		}
		MPTCP_LOG("\tlazytail_steps_behind returning 0 because we are ahead of send_head\n");
		return 0;
	}

	MPTCP_LOG("\tlazytail_steps_behind returning -1 because previous = NULL\n");
	return -2;
}


/* return the skb pointer advanced n steps in the queue */
static struct sk_buff *lazytail_advance_skb(struct sk_buff *skb, int num_steps)
{
	int i;
	for (i=0; i<num_steps; i++) {
		skb = skb->next;
	}
	return skb;
}



/*
 * Returns the next skb from the lazytail pointer into the queue.
 *
 * If it finds that the lazytail has caught up with the monkeyhead
 * (or caught up to the last jump for this subflow) then it marks them as
 * synced and returns a skb from the monkeyhead.
 *
 * Returns NULL if there is nothing to send, or if lazytail catches
 * up with monkeyead.  Generally, if this function returns NULL, you should
 * call lazytail_next_skb_from_monkeyhead() afterward because there may
 * still be packets up these to send.
 *
 * Should not call this unless (!sk_data->lazytail_synced) because the
 * necessary fields in sk_data may not be set.  But if you do, it will
 * catch it and just return NULL.
 */
/*
 * skb = lazytail_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *lazytail_next_skb_from_lazytail(struct sk_buff_head *queue,
						     struct lazytailsched_sock_data *sk_data,
						     struct sock *meta_sk)
{
	struct sk_buff *previous;
	struct sk_buff *skb;

	MPTCP_LOG("\tmonkeytail_next_skb_from_MONKEYTAIL\n");

	/* this function will only work if monkeyhead and monkeytail are out of sync */
	if (sk_data->lazytail_synced) {
		MPTCP_LOG("\t\treturning NULL because lazytail_synced\n");
		return NULL;
	}

	/* if the last segment sent from tail is the same as the last segment sent from head, we
	 * are already synced. */
	if (sk_data->lazytail_skb == sk_data->monkeyhead_skb) {
		MPTCP_LOG("\t\treturning NULL because lazytail_skb == monkeyhead_skb\n");
		if (!sk_data->lazytail_synced) {
			MPTCP_LOG2("\t\t\t\t 1 set sk_data->lazytail_synced = true");
			MPTCP_LOG2("\t\t\t\t tail\t%p\n",sk_data->lazytail_skb);
			MPTCP_LOG2("\t\t\t\t head\t%p\n",sk_data->monkeyhead_skb);
		}
		sk_data->lazytail_synced = true;
		return NULL;
	}

	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\t\treturning NULL because skb_queue_empty()\n");
		return NULL;
	}

	previous = sk_data->lazytail_skb;

	if (!previous) {
		/* The previous monkeytail packet disappeared, presumably because it was ACKed. */
		/* Check if the new oldest un-ACKed packet has caught up monkeyhead, or with the
		 * last jump of monkeyhead
		 */
		MPTCP_LOG("\t\tprevious monkeytail = NULL\n");
		skb = skb_peek(queue);
		if (skb == NULL) {
			if (!sk_data->lazytail_synced) { MPTCP_LOG2("\t\t\t\t 2 set sk_data->lazytail_synced = true"); }
			sk_data->lazytail_synced = true;
			return NULL;
		}

	} else {
		MPTCP_LOG("\t\tprevious monkeytail != NULL\n");

		/* if the last packet sent was the last in the queue, we must be synced */
		if (skb_queue_is_last(queue, previous)) {
			MPTCP_LOG("\t\treturning NULL because skb_queue_is_last()\n");
			if (!sk_data->lazytail_synced) { MPTCP_LOG2("\t\t\t\t 3 set sk_data->lazytail_synced = true"); }
			sk_data->lazytail_synced = true;
			return NULL;
		}

		/* check if the previously scheduled segment was send_head, and not sent */
		if (tcp_send_head(meta_sk) == previous) {
			MPTCP_LOG("\t\t monkeytail_next_skb_from_monkeytail() returning tcp_send_head(meta_sk)\n");
			skb = tcp_send_head(meta_sk);
		} else {
			MPTCP_LOG("\t\t monkeytail_next_skb_from_monkeytail() returning skb_queue_next(queue, previous)\n");
			skb = skb_queue_next(queue, previous);
		}
	}

	//XXX just in case - remove later
	if (skb==NULL) {
		pr_info("ERROR: monkeytail_next_skb_from_monkeytail() got skb=NULL!\n");
		return NULL;
	}

	/* see if the start of skb has caught up (or passed) with the last jump */
	if (! before(TCP_SKB_CB(skb)->seq, sk_data->monkeyhead_last_jump_seq)) {
		MPTCP_LOG("\t\t\tmonkeytail has caught up with most recent jump\n");
		if (!sk_data->lazytail_synced) {
			MPTCP_LOG2("\t\t\t\t 4 set sk_data->lazytail_synced = true");
			MPTCP_LOG2("\t\t\t\t tail seq:\t%u\t%u\n",TCP_SKB_CB(skb)->seq,TCP_SKB_CB(skb)->end_seq);
			MPTCP_LOG2("\t\t\t\t jump seq:\t%u\n",sk_data->monkeyhead_last_jump_seq);
		}
		sk_data->lazytail_synced = true;
		return NULL;
	}

	/* see if the start of skb has caught up (or passed) the monkeyhead */
	if (! before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(sk_data->monkeyhead_skb)->seq)) {
		MPTCP_LOG("\t\t\tmonkeytail has caught up with monkeyhead seq\n");
		sk_data->lazytail_synced = true;
		if (!sk_data->lazytail_synced) { MPTCP_LOG2("\t\t\t\t 5 set sk_data->lazytail_synced = true"); }
		// return = service the head
		return NULL;
	}

	// if we are not already caught up, the rest of this code checks if sending this next
	//segment will get us caught up to last_jump or monkeyhead it should be moved somewhere else

	/* check if sending this segment will catch us up with the last jump */
	/*if (! before(TCP_SKB_CB(skb)->end_seq, sk_data->monkeyhead_last_jump_seq)) {  //monkeyhead_last_jump_seq should be the seq at the start of the packet
		MPTCP_LOG("\t\t\tmonkeytail will catch up with most recent jump after sending this segment\n");
		*tmp_lazytail_synced = true;
	}*/

	/* check if sending this segment will catch us up with the head */
	/*if (! before(TCP_SKB_CB(skb)->end_seq, TCP_SKB_CB(sk_data->monkeyhead_skb)->seq)) {
		MPTCP_LOG("\t\t\tmonkeytail will catch up with monkeyhead seq after sending this segment\n");
		*tmp_lazytail_synced = true;
	}*/

	return skb;
}


/*
 * Returns the next skb from the monkeyhead pointer into the queue.
 *
 * If it finds that the monkeyhead has fallen too far behind sk_send_head, it
 * jumps up to MAX_LAG steps behind it, but it leaves its lazytail behind.
 * If the monkeyhead and lazytail were synced it leaves the monkey tail at
 * monkeyhead's previous location.
 * If monkeyhead and lazytail are not synced it leaves lazytail right
 * where it is.
 */
/*
 * skb = lazytail_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *lazytail_next_skb_from_monkeyhead(struct sk_buff_head *queue,
						     struct lazytailsched_sock_data *sk_data,
						     struct sock *meta_sk,
							 bool *monkeyhead_jumped)
{
	int lag = 0;
	u32 MAX_LAG = sysctl_mptcp_maxlag;
	struct sk_buff *send_head = tcp_send_head(meta_sk);
	struct sk_buff *skb = NULL;
	struct sk_buff *previous;
	u32 i;
	//*send_head_again = false;

	MPTCP_LOG("\tmonkeytail_next_skb_from_MONKEYHEAD\n");
	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\treturning NULL because skb_queue_empty()\n");
		if (!sk_data->lazytail_synced) { MPTCP_LOG2("\t\t\t\t 6 set sk_data->lazytail_synced = true"); }
		sk_data->lazytail_synced = true;
		return NULL;
	}

	previous = sk_data->monkeyhead_skb;
	*monkeyhead_jumped = false;

	if (previous != NULL) {

		MPTCP_LOG("\t\tprevious != NULL\n");

		/* check if this subflow is has already sent the tail of the queue */
		if (skb_queue_is_last(queue, previous)) {
			MPTCP_LOG("\t\treturning NULL because previous!=NULL and skb_queue_is_last()\n");
			return NULL;
		}

		/* if we are not at the tail, check how far back from the send_head we are */
		lag = lazytail_steps_behind(queue, previous, meta_sk);

		/* If lag==0 then previous==send_head and we need to try sending send_head again */
		if (previous == tcp_send_head(meta_sk)) {
			MPTCP_LOG("\t\treturning previous because (previous == tcp_send_head(meta_sk))  %p  %p\n",previous,tcp_send_head(meta_sk));
			//*send_head_again = true;
			return previous;
		}

		/* if necessary, catch up with the leading subflow */
		if ((lag > 0) && (lag > MAX_LAG)) {
			MPTCP_LOG("\t\treturning previous advanced by %d steps\n", (lag - MAX_LAG));
			if ((lag-MAX_LAG) > 1) {
				*monkeyhead_jumped = true;

				/* If the head and tail were synced before, if this skb gets sent, they will be un-synced.
				 * Initialize the tail to the place we're jumping from.  Don't set sk_data->lazytail_synced.
				 * That will be set later if this skb is actually scheduled on the subflow.
				 * sk_data->monkeyhead_last_jump_seq  will be set later too, if this segment is actually sent. */
				if (sk_data->lazytail_synced) {
					sk_data->lazytail_skb = previous;
					sk_data->lazytail_skb_end_seq = TCP_SKB_CB(sk_data->lazytail_skb)->end_seq;
				}
			}
			return lazytail_advance_skb(previous, lag-MAX_LAG);
		}

		/* otherwise just send the next thing in our queue */
		MPTCP_LOG("\t\treturning skb_queue_next(queue, previous);\n");
		return skb_queue_next(queue, previous);
	}

	/* previous is null.
	 * This means that the last segment we sent from the monkeyhead has been ACKed.
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

	/* If we did not backtrack to the head of the queue, then the monkey tail is implicitly
	 * there now, and if this segment is sent we will be un-synced. */
	if (skb != skb_peek(queue)) {
		sk_data->lazytail_skb = NULL;
		sk_data->lazytail_skb_end_seq = TCP_SKB_CB(skb_peek(queue))->seq - 1;
	}
	*monkeyhead_jumped = true;

	MPTCP_LOG("\t\treturning backtracked %d steps from tcp_send_head(meta_sk)\n",i);
	return skb;
}

static struct tcp_sock *get_selected_monkey(struct mptcp_cb *mpcb){
	struct tcp_sock *tp;
	struct tcp_sock *first_tp = mpcb->connection_list;
	struct tcp_sock *selected_monkey = NULL;
	int min_cap= INT_MAX;
	int min_rtt= INT_MAX;
	int max_cap= 0;
	int max_rtt= 0;
	struct lazytailsched_sock_data *sk_data;

	if (!first_tp) {
		MPTCP_LOG("\tmonkeytail_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}
	int flow_count=0;
	tp=first_tp;
	do{
//		trace_printk("tp %p rtt %d desire %d\n",tp,tp->srtt_us>>3,DESIRE_DELAY);
		int sf_capacity= 0;
		int rtt=tp->srtt_us>>3;
		if (tp->rate_interval_us>0){
			sf_capacity=tp->rate_delivered*1000000/tp->rate_interval_us;
		}
		if (sf_capacity <= min_cap){
			min_cap=sf_capacity;
			selected_monkey=tp;
		}
		if (sf_capacity >= max_cap){
			max_cap = sf_capacity;
		}
		if(rtt>max_rtt){
			max_rtt = rtt;

		}
		if(rtt<min_rtt){
			min_rtt=rtt;
		}
		tp = tp->mptcp->next;
		if (!tp){
			tp = mpcb->connection_list;
		}
		flow_count++;
	} while (tp != first_tp);
	if (flow_count==1){
		return NULL;
	}

	sk_data = lazytailsched_get_sock_data(selected_monkey);
	sk_data->leading_subsk_rtt=max_rtt;
	return selected_monkey;
}


/*
 * Two big dilemmas for this scheduler:
 *
 * - When there is a leading flow, how to keep the tail synced with the head?
 *   In this case when the head sends a packet, the tail has to advance too.
 *   When the head jumps ahead and the tail gets left behind, then sending
 *   on the head does not advance the tail.  But we need to watch for the
 *   tail catching up so we can put them back in sync.
 *
 * - When the head skips ahead and the tail is left behind, how can we tell
 *   what packets were sent by the head?  It leaves no record.  If the tail
 *   needs to re-send *everything* to catch up, then if the leading flow
 *   gets out of sync, you could end up in a situation of re-sending
 *   everything, and never being able to catch up.
 *   Proposed solution: Keep a record of the head's most recent jump (the
 *   landing point).  The idea is that the head has already sent every packet
 *   between this point and its current location.  If the tail catches up to
 *   this point, by catching up or ACK, then the tail is considered synced
 *   with the head again.
 *   Otherwise, in the case where one flow is consistently lagging, we accept
 *   that the tail will resend packets that have been sent by the head.  In
 *   the case of a lagging subflow, the tail is sending much older packets,
 *   there is a good chance they are dropped anyway.
 *
 */
static struct sk_buff *lazytail_next_segment(struct sock *meta_sk,
					      int *reinject,
					      struct sock **subsk,
					      unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct lazytailsched_cb_data *cb_data = lazytailsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int active_valid_sks = -1;
	struct tcp_sock *monkey_sf=NULL;
	//u32 TAIL_SERVICE_INTERVAL = sysctl_mptcp_tail_service_interval;

	MPTCP_LOG("********************* lazytail_next_segment *********************\n");
	//MPTCP_LOG("\tstarting with first_tp=%p\n",first_tp);

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
	    skb_queue_empty(&meta_sk->sk_write_queue)) {
		/* Nothing to send */
		MPTCP_LOG("\tlazytail_next_segment return NULL because skb_queue_empty()\n");
		return NULL;
	}

	/* First try reinjections */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk) {
			MPTCP_LOG("\tlazytail_next_segment return NULL because (!*subsk)\n");
			return NULL;
		}
		*reinject = 1;
		MPTCP_LOG("\tlazytail_next_segment return reinject sk_buff %p and sock %p\n", skb, *subsk);
		return skb;
	}

	/* Then try indistinctly redundant and normal skbs */

	if (!first_tp) {
		first_tp = mpcb->connection_list;
		//MPTCP_LOG("\tfirst_tp undefined.  setting first_tp = mpcb->connection_list=%p\n",first_tp);
	}

	/* still NULL (no subflow in connection_list?) */
	if (!first_tp) {
		MPTCP_LOG("\tlazytail_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}

	tp = first_tp;

	*reinject = 0;
	active_valid_sks = lazytailsched_get_active_valid_sks(meta_sk);


	do {
		struct lazytailsched_sock_data *sk_data;
		bool packet_from_lazytail;
		bool monkeyhead_jumped;
		MPTCP_LOG("    ******** lazytail_next_segment trying sock %p ********\n", tp);

		/* Correct the skb pointers of the current subflow */
		sk_data = lazytailsched_get_sock_data(tp);
		if (sk_data == NULL) {
			MPTCP_LOG("\tERROR: sk_data == NULL\n");
		}
		lazytailsched_correct_skb_pointers(meta_sk, sk_data);

		//update monkey
		monkey_sf= get_selected_monkey(mpcb);

		skb = NULL;
		packet_from_lazytail = false;
		//MPTCP_LOG("\ttry to get an sk_buff from the queue\n");
		MPTCP_LOG("\tlazytail_synced = %d   lazytail_service_counter = %d\n", sk_data->lazytail_synced, sk_data->lazytail_service_counter);
		if (sk_data->lazytail_synced) {
			/* if monkeyhead and lazytail are synced, just service the head */
			skb = lazytail_next_skb_from_monkeyhead(&meta_sk->sk_write_queue, sk_data, meta_sk, &monkeyhead_jumped);

		} else {
			//calculate tail-send-gap
//			if (!monkey_sf || tp == monkey_sf){
//				struct sk_buff *send_tail = skb_peek(&meta_sk->sk_write_queue);
//				struct skb_mstamp now;
//				skb_mstamp_get(&now);
//				if (send_tail){
//					MPTCP_LOG("\t QueueLen %d\n",skb_mstamp_us_delta(&now, &(send_tail->skb_mstamp)));
//				}
//				int rtt=tp->srtt_us>>3;
//				if (send_tail && skb_mstamp_us_delta(&now, &(send_tail->skb_mstamp))>(sk_data->leading_subsk_rtt/2+rtt/2) ){
//
//					sk_data->recover_mode=true;
//
//				}else{
//					sk_data->recover_mode=false;
//					sk_data->recover_sent=false;
//				}
//
//			}
			/* if they are not synced, we only service the tail when it has been overtaken by ACKs */
			if (! sk_data->lazytail_skb) {
//			if (!sk_data->lazytail_skb && sk_data->recover_mode && !sk_data->recover_sent) {
				/* try to get a packet from the tail */
				skb = lazytail_next_skb_from_lazytail(&meta_sk->sk_write_queue, sk_data, meta_sk);
				sk_data->recover_sent=true;
				packet_from_lazytail = true;
			}
			/* if we failed to get one from the tail, we still need to try the head */
			if (!skb) {
				skb = lazytail_next_skb_from_monkeyhead(&meta_sk->sk_write_queue, sk_data, meta_sk, &monkeyhead_jumped);
				packet_from_lazytail = false;
			}
		}

		MPTCP_LOG("\tlazytail_next_skb_from_queue returned %p\n", skb);
		MPTCP_LOG("\tlazytail_synced=%d  monkeyhead=%p  lazytail=%p\n",sk_data->lazytail_synced,sk_data->monkeyhead_skb,sk_data->lazytail_skb);

		if (skb && lazytailsched_use_subflow(meta_sk, active_valid_sks, tp, skb)) {
			MPTCP_LOG("\t\tlazytailsched_use_subflow is:\t\t\t\t\t\t\tTRUE!\n");
			if (packet_from_lazytail) {
				MPTCP_LOG2("++++ sending on %p\ttail\t%d\n", tp, sk_data->lazytail_synced);
				MPTCP_LOG("\t\tpacket_from_lazytail\n");

				/* check if this segment will catch the tail up with the last jump */
				if (! before(TCP_SKB_CB(skb)->end_seq + 1, sk_data->monkeyhead_last_jump_seq)) {
					MPTCP_LOG("\t\t\tmonkeytail will catch up with most recent jump after sending this segment\n");
					if (!sk_data->lazytail_synced) { MPTCP_LOG2("\t\t\t\t 7 set sk_data->lazytail_synced = true"); }
					sk_data->lazytail_synced = true;
				}

				/* check if sending this segment will catch us up with the monkeyhead's previous segment */
				if (sk_data->monkeyhead_skb) {
					if (! before(TCP_SKB_CB(skb)->end_seq + 1, TCP_SKB_CB(sk_data->monkeyhead_skb)->seq)) {
						MPTCP_LOG("\t\t\tmonkeytail will catch up with monkeyhead seq after sending this segment\n");
						if (!sk_data->lazytail_synced) { MPTCP_LOG2("\t\t\t\t 8 set sk_data->lazytail_synced = true"); }
						sk_data->lazytail_synced = true;
					}
				}

				sk_data->lazytail_service_counter = 0;
				sk_data->lazytail_skb = skb;
				sk_data->lazytail_skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			} else {
				MPTCP_LOG2("++++ sending on %p\thead\t%d\n", tp, sk_data->lazytail_synced);
				MPTCP_LOG("\t\tNOT packet_from_lazytail\n");
				sk_data->lazytail_service_counter++;
				if (monkeyhead_jumped) {
					MPTCP_LOG("\t\tmonkeyhead_jumped!\n");
					if (sk_data->lazytail_synced) {
						MPTCP_LOG2("\t\t\t\t head jump desync\t%u\n",TCP_SKB_CB(skb)->seq);
					}
					sk_data->lazytail_synced = false;

					/* record the place where we jumped to */
					sk_data->monkeyhead_last_jump_seq = TCP_SKB_CB(skb)->seq;
					MPTCP_LOG("\t\tmonkeyhead_last_jump_seq = %u\n",sk_data->monkeyhead_last_jump_seq);
				}
				sk_data->monkeyhead_skb = skb;
				sk_data->monkeyhead_skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			}

			cb_data->next_subflow = tp->mptcp->next;
			//MPTCP_LOG("\t\tfirst_tp setting cb_data->next_subflow=%p\n",cb_data->next_subflow);
			*subsk = (struct sock *)tp;

			if (TCP_SKB_CB(skb)->path_mask)
				*reinject = -1;
			MPTCP_LOG("\tlazytail_next_segment return sk_buff %p and sock %p\n", skb, *subsk);
			return skb;
		} else {
			MPTCP_LOG("\tlazytail_next_segment skipping because !skb or !use_subflow is \t\t\tFALSE!");
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	MPTCP_LOG("\tlazytail_next_segment return NULL (end of function)\n");
	return NULL;
}

static void lazytail_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lazytailsched_cb_data *cb_data = lazytailsched_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	 * the pointer
	 */
	if (cb_data->next_subflow == tp)
		cb_data->next_subflow = tp->mptcp->next;
}

static struct mptcp_sched_ops mptcp_sched_lazytail = {
	.get_subflow = lazytail_get_subflow,
	.next_segment = lazytail_next_segment,
	.release = lazytail_release,
	.name = "lazytail",
	.owner = THIS_MODULE,
};

static int __init lazytail_register(void)
{
	MPTCP_LOG("lazytail_register\n");
	BUILD_BUG_ON(sizeof(struct lazytailsched_sock_data) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct lazytailsched_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_lazytail))
		return -1;

	return 0;
}

static void lazytail_unregister(void)
{
	MPTCP_LOG("lazytail_unregister\n");
	mptcp_unregister_scheduler(&mptcp_sched_lazytail);
}

module_init(lazytail_register);
module_exit(lazytail_unregister);

MODULE_AUTHOR("Brenton Walker");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LAZYTAIL REDUNDANT MPTCP");
MODULE_VERSION("0.90");
