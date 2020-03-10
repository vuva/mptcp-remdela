/*
 * mptcp_monkeytail.c
 *
 *  Created on: Mar 19, 2018
 *      Author: brenton
 */


/*
 *	MPTCP Scheduler to reduce latency and jitter.
 *
 *
 *  This is the monkeytail redundant scheduler.  It is a hybrid of tagalong and redundant.
 *  Each subflow maintains two pointers into the ring of un-ACKed packets.
 *  The (monkey's) head behaves like tagalong, skipping ahead to keep up with the
 *  fastest flow.  The monkey's tail stays behind pointing to the oldest un-ACKed packet
 *  that has not been sent on this subflow.
 */

#include <linux/module.h>
#include <net/mptcp.h>
#include <net/tcp.h>

#define MPTCP_DEBUG
#ifdef MPTCP_DEBUG
#define MPTCP_LOG(...) pr_info(__VA_ARGS__)
#else
#define MPTCP_LOG(...)
#endif

#define HEAD_MODE 1
#define FOLLOW_MODE 2
#define TAIL_MODE 3

//#define TAIL_SERVICE_INTERVAL 2

/* Struct to store the data of a single subflow
 * This is larger than 16 bytes and required increading MPTCP_SCHED_SIZE in mptcp.h.
 */
struct monkeytailsched_sock_data {
	/* The skb (or NULL) that tries to keep up with the leading flow */
	struct sk_buff *monkeyhead_skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 monkeyhead_skb_end_seq;

	/* The skb (or NULL) that tracks the oldest un-ACKed packet not sent on this flow */
	struct sk_buff *monkeytail_skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 monkeytail_skb_end_seq;

	/* This flag indicates whether the head and tail are in sync or not. */
	bool monkeytail_synced;

	/* When the head and tail are not synced, the keeps track of the last place the head jumped to. */
	u32 monkeyhead_last_jump_seq;

	/* Keep track of the number of monkeyhead packets sent since the last monkeytail service */
	u32 monkeytail_service_counter;
	u32 monkeyhead_service_counter;

	u32 head_count;
	u32 tail_count;
	u32 queue_head_count;
	u32 estimated_throughput;
	bool is_monkey;
	bool recover_mode;
	bool recover_sent;
	u32 monkey_mode;
	u32 leading_subsk_rate;
	u32 leading_subsk_rtt;
};

struct subflow_lag{
	int steps;
	int size;
	long catch_up_time;// in us
	int max_lag;
};

/* Struct to store the data of the control block */
struct monkeytailsched_cb_data {
	/* The next subflow where a skb should be sent or NULL */
	struct tcp_sock *next_subflow;
};

/* Returns the socket data from a given subflow socket */
static struct monkeytailsched_sock_data *monkeytailsched_get_sock_data(struct tcp_sock *tp)
{
	return (struct monkeytailsched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

/* Returns the control block data from a given meta socket */
static struct monkeytailsched_cb_data *monkeytailsched_get_cb_data(struct tcp_sock *tp)
{
	return (struct monkeytailsched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static bool monkeytailsched_get_active_valid_sks(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	int active_valid_sks = 0;

	//MPTCP_LOG("monkeytailsched_get_active_valid_sks\n");
	mptcp_for_each_sk(mpcb, sk) {
		if (subflow_is_active((struct tcp_sock *)sk) &&
		    !mptcp_is_def_unavailable(sk))
			active_valid_sks++;
	}

	//if (active_valid_sks) {
	//	MPTCP_LOG("\tmonkeytailsched_get_active_valid_sks returning active_valid_sks = TRUE\n");
	//} else {
	//	MPTCP_LOG("\tmonkeytailsched_get_active_valid_sks returning active_valid_sks = FALSE\n");
	//}
	return active_valid_sks;
}

static bool monkeytailsched_use_subflow(struct sock *meta_sk,
				 int active_valid_sks,
				 struct tcp_sock *tp,
				 struct sk_buff *skb)
{
	//MPTCP_LOG("\tmonkeytailsched_use_subflow\n");

	if (!skb || !mptcp_is_available((struct sock *)tp, skb, false)) {
		//MPTCP_LOG("\t\tmonkeytailsched_use_subflow returning FALSE because !mptcp_is_available\n");
		return false;
	}

	if (TCP_SKB_CB(skb)->path_mask != 0) {
		//MPTCP_LOG("\t\tmonkeytailsched_use_subflow returning subflow_is_active(tp)\n");
		return subflow_is_active(tp);
	}

	if (TCP_SKB_CB(skb)->path_mask == 0) {
		if (active_valid_sks == -1)
			active_valid_sks = monkeytailsched_get_active_valid_sks(meta_sk);

		if (subflow_is_backup(tp) && active_valid_sks > 0) {
			//MPTCP_LOG("\t\tmonkeytailsched_use_subflow returning FALSE because (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return false;
		} else {
			//MPTCP_LOG("\t\tmonkeytailsched_use_subflow returning TRUE because NOT (subflow_is_backup(tp) && active_valid_sks > 0)\n");
			return true;
		}
	}

	return false;
}

static struct sock *monkeytail_get_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct monkeytailsched_cb_data *cb_data = monkeytailsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct sock *sk;
	struct tcp_sock *tp;

	MPTCP_LOG("monkeytail_get_subflow\n");

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
static void monkeytailsched_correct_skb_pointers(struct sock *meta_sk,
					  struct monkeytailsched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	//MPTCP_LOG("\tmonkeytailsched_correct_skb_pointers\n");

	if (sk_data->monkeyhead_skb && !after(sk_data->monkeyhead_skb_end_seq, meta_tp->snd_una)) {
		sk_data->monkeyhead_skb = NULL;
		//MPTCP_LOG("\t\tmonkeytailsched_correct_skb_pointers setting sk_data->monkeyhead_skb = NULL\n");
	}
	if (! sk_data->monkeytail_synced) {
		//MPTCP_LOG("\t\tmonkeytailsched_correct_skb_pointers: !sk_data->monkeytail_synced\n");
		if (sk_data->monkeytail_skb && !after(sk_data->monkeytail_skb_end_seq, meta_tp->snd_una)) {
			sk_data->monkeytail_skb = NULL;
			//MPTCP_LOG("\t\tmonkeytailsched_correct_skb_pointers setting sk_data->monkeytail_skb = NULL\n");
		}
	}
}



/* Compute the number of packets between previous and the current sk_send_head,
 * or, if sksend_head is . */
static struct subflow_lag monkeytail_steps_behind(struct sk_buff_head *queue,
								struct sk_buff *previous,
								struct sock *meta_sk, struct tcp_sock *sub_sk,u32 leading_subsk_rate, u32 leading_subsk_rtt)
{
	struct sk_buff *send_head = tcp_send_head(meta_sk);
	struct sk_buff *send_tail = skb_peek_tail(queue);
	struct subflow_lag init = {0, 0, 0, 0};
	struct subflow_lag lag = init;
	struct skb_mstamp now;
//	struct rate_sample rs = { .prior_delivered = 0 };
	int sRTT ;
	long estimated_throughput= 0L;
	u32 DESIRE_DELAY = sysctl_mptcp_desired_latency;
	int avg_pkt_size = 1427;
	skb_mstamp_get(&now);
//	if (sub_sk){
//		estimated_throughput=(long)monkeytailsched_get_sock_data(sub_sk)->estimated_throughput;
//		trace_printk("\testimated_throughput %ld \n",estimated_throughput);
//	}


	MPTCP_LOG("\tmonkeytail_steps_behind\n");
//	MPTCP_LOG("\t\tsend_head=%p  send_tail=%p\n",send_head,send_tail);

	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\t\tmonkeytail_steps_behind returning -1 because skb_queue_empty()\n");
		return lag;
	}

	/* If send_head is null, every segment in the queue has been sent.
	 * Use send_tail as the reference point for computing lag. */
	if (send_head == NULL) {
		//MPTCP_LOG("\t\tmonkeytail_steps_behind returning -1 because send_head is NULL\n");
		//return -1;
		MPTCP_LOG("\t\tmonkeytail_steps_behind: send_head is NULL.  Using send_tail for computing lag\n");
		//send_head = send_tail;
	}
	sRTT = (int)(sub_sk->srtt_us>>3);
//	if ( (DESIRE_DELAY>leading_subsk_rtt/2) && (DESIRE_DELAY<(leading_subsk_rtt/2+sRTT))){
//		DESIRE_DELAY=leading_subsk_rtt/2;
//	}
//		else if( DESIRE_DELAY<leading_subsk_rtt/2){
//			DESIRE_DELAY=0;
//		}
//		long queue_length = skb_mstamp_us_delta(&now, &(previous->skb_mstamp));

	if( DESIRE_DELAY<leading_subsk_rtt/2){
		DESIRE_DELAY=sRTT/2;
	}

	if (previous != NULL) {
		/* count how many steps we can advance previous until it
		 * reaches either send_head or send_tail */
//		if(previous == send_head ){
//			MPTCP_LOG("\t\t drizzle check previous is head \n");
//		}
//		if(previous == send_tail ){
//			MPTCP_LOG("\t\t drizzle check previous is tail \n");
//		}
		if (previous == send_tail && previous->next!=send_tail){
			lag.steps ++;
			previous = previous->next;
		}
		while (previous != send_head && previous != send_tail) {
			lag.steps ++;
			previous = previous->next;
		}
//		MPTCP_LOG("\t\t drizzle check previous and head \t%p \t%p\n", previous,send_head);
		if (send_head == NULL || previous == send_head) {
//			MPTCP_LOG("\tmonkeytail_steps_behind returning %d\n",lag.steps);
//			MPTCP_LOG("\t\tcheck prev before %p ->prev %p\n", previous, previous->prev);
			int i;
			for(i=0;i<lag.steps;i++){
				previous = previous->prev;

				if (!previous ||  previous == send_head){
					break;
				}

				lag.max_lag=i;
				lag.size = lag.size + previous->len;
	//			avg_pkt_size= lag.size/i;
				if (sub_sk && leading_subsk_rate>0 && sub_sk->rate_delivered>0){
	//				estimated_throughput = (long)sub_sk->rate_delivered*avg_pkt_size*8*1000000/sub_sk->rate_interval_us;previous->len *8*1000000/estimated_throughput + sub_sk->rate_interval_us/sub_sk->rate_delivered ; sub_sk->rate_interval_us/sub_sk->rate_delivered;
					lag.catch_up_time = skb_mstamp_us_delta(&now, &(previous->skb_mstamp)) + sRTT/2 ;
					MPTCP_LOG("\t %d leadrate %d delta %d trans_time %d catch_up_time %ld\n",i,leading_subsk_rate, skb_mstamp_us_delta(&now, &(previous->skb_mstamp)),sub_sk->rate_interval_us/sub_sk->rate_delivered ,lag.catch_up_time );
				}
				if (lag.catch_up_time > DESIRE_DELAY){
//					if (previous->prev && previous == send_head){
//						previous = previous->prev;
//					}
//					if (lag.max_lag>0){
//						lag.max_lag=lag.max_lag-1;
//					}
					break;
				}
			}
		}

		MPTCP_LOG("\tsub_sk %p steps %d size %d rate %ld rtt %d cut %ld maxlag %d avg_pkt_size %d maxrtt %d\n", sub_sk, lag.steps, lag.size, estimated_throughput, sRTT, lag.catch_up_time, lag.max_lag, avg_pkt_size,leading_subsk_rtt );
		return lag;
	}

	MPTCP_LOG("\tmonkeytail_steps_behind returning -1 because previous = NULL\n");
	return lag;
}


/* return the skb pointer advanced n steps in the queue */
static struct sk_buff *monkeytail_advance_skb(struct sk_buff *skb, int num_steps)
{
	int i;
	for (i=0; i<num_steps; i++) {
		skb = skb->next;
	}
	return skb;
}



/*
 * Returns the next skb from the monkeytail pointer into the queue.
 *
 * If it finds that the monkeytail has caught up with the monkeyhead
 * (or caught up to the last jump for this subflow) then it marks them as
 * synced and returns a skb from the monkeyhead.
 *
 * Returns NULL if there is nothing to send, or if monkeytail catches
 * up with monkeyead.  Generally, if this function returns NULL, you should
 * call monkeytail_next_skb_from_monkeyhead() afterward because there may
 * still be packets up these to send.
 *
 * Should not call this unless (!sk_data->monkeytail_synced) because the
 * necessary fields in sk_data may not be set.  But if you do, it will
 * catch it and just return NULL.
 */
/*
 * skb = monkeytail_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *monkeytail_next_skb_from_monkeytail(struct sk_buff_head *queue,
						     struct monkeytailsched_sock_data *sk_data,
						     struct sock *meta_sk)
{
	struct sk_buff *previous;
	struct sk_buff *skb;

	MPTCP_LOG("\tmonkeytail_next_skb_from_MONKEYTAIL\n");

	/* this function will only work if monkeyhead and monkeytail are out of sync */
	if (sk_data->monkeytail_synced) {
		MPTCP_LOG("\t\treturning NULL because monkeytail_synced\n");
		return NULL;
	}

	/* if the last segment sent from tail is the same as the last segment sent from head, we
	 * are already synced. */
	if (sk_data->monkeytail_skb == sk_data->monkeyhead_skb) {
		MPTCP_LOG("\t\treturning NULL because monkeytail_skb == monkeyhead_skb\n");
		sk_data->monkeytail_synced = true;
		return NULL;
	}

	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\t\treturning NULL because skb_queue_empty()\n");
		return NULL;
	}

	previous = sk_data->monkeytail_skb;

	if (!previous) {
		/* The previous monkeytail packet disappeared, presumably because it was ACKed. */
		/* Check if the new oldest un-ACKed packet has caught up monkeyhead, or with the
		 * last jump of monkeyhead
		 */
		MPTCP_LOG("\t\tprevious monkeytail = NULL\n");
		skb = skb_peek(queue);
		if (skb == NULL) {
			sk_data->monkeytail_synced = true;
			return NULL;
		}

	} else {
		MPTCP_LOG("\t\tprevious monkeytail != NULL\n");

		/* if the last packet sent was the last in the queue, we must be synced */
		if (skb_queue_is_last(queue, previous)) {
			MPTCP_LOG("\t\treturning NULL because skb_queue_is_last()\n");
			sk_data->monkeytail_synced = true;
			return NULL;
		}

		/* check if the previously scheduler segment was send_head, and not sent */
		if (tcp_send_head(meta_sk) == previous) {
			MPTCP_LOG("\t\t monkeytail_next_skb_from_monkeytail()returning tcp_send_head(meta_sk)\n");
			skb = tcp_send_head(meta_sk);
		} else {
			MPTCP_LOG("\t\t monkeytail_next_skb_from_monkeytail()returning skb_queue_next(queue, previous)\n");
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
		sk_data->monkeytail_synced = true;
		return NULL;
	}

	/* see if the start of skb has caught up (or passed) the monkeyhead */
	if (! before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(sk_data->monkeyhead_skb)->seq)) {
		MPTCP_LOG("\t\t\tmonkeytail has caught up with monkeyhead seq\n");
		sk_data->monkeytail_synced = true;
		// return = service the head
		return NULL;
	}

	// if we are not already caught up, the rest of this code checks if sending this next
	//segment will get us caught up to last_jump or monkeyhead it should be moved somewhere else

	/* check if sending this segment will catch us up with the last jump */
	/*if (! before(TCP_SKB_CB(skb)->end_seq, sk_data->monkeyhead_last_jump_seq)) {  //monkeyhead_last_jump_seq should be the seq at the start of the packet
		MPTCP_LOG("\t\t\tmonkeytail will catch up with most recent jump after sending this segment\n");
		*tmp_monkeytail_synced = true;
	}*/

	/* check if sending this segment will catch us up with the head */
	/*if (! before(TCP_SKB_CB(skb)->end_seq, TCP_SKB_CB(sk_data->monkeyhead_skb)->seq)) {
		MPTCP_LOG("\t\t\tmonkeytail will catch up with monkeyhead seq after sending this segment\n");
		*tmp_monkeytail_synced = true;
	}*/

	return skb;
}


/*
 * Returns the next skb from the monkeyhead pointer into the queue.
 *
 * If it finds that the monkeyhead has fallen too far behind sk_send_head, it
 * jumps up to MAX_LAG steps behind it, but it leaves its monkeytail behind.
 * If the monkeyhead and monkeytail were synced it leaves the monkey tail at
 * monkeyhead's previous location.
 * If monkeyhead and monkeytail are not synced it leaves monkeytail right
 * where it is.
 */
/*
 * skb = monkeytail_next_skb_from_queue(&meta_sk->sk_write_queue, sk_data->skb, meta_sk);
 */
static struct sk_buff *monkeytail_next_skb_from_monkeyhead(struct sk_buff_head *queue,
						     struct monkeytailsched_sock_data *sk_data,
						     struct sock *meta_sk, struct tcp_sock *sub_sk,
							 bool *monkeyhead_jumped)
{
	struct subflow_lag lag;
	u32 MAX_LAG = sysctl_mptcp_maxlag;
	struct sk_buff *send_head = tcp_send_head(meta_sk);
	struct sk_buff *skb = NULL;
	struct sk_buff *previous;
	u32 i;
//	u32 TAIL_SERVICE_INTERVAL = sysctl_mptcp_tail_service_interval;
	u32 DESIRE_DELAY = sysctl_mptcp_desired_latency;
	//*send_head_again = false;

	MPTCP_LOG("\tmonkeytail_next_skb_from_MONKEYHEAD\n");
	if (skb_queue_empty(queue)) {
		MPTCP_LOG("\treturning NULL because skb_queue_empty()\n");
		sk_data->monkeytail_synced = true;
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
		lag = monkeytail_steps_behind(queue, previous, meta_sk,sub_sk,sk_data->leading_subsk_rate, sk_data->leading_subsk_rtt);
		/* If lag==0 then previous==send_head and we need to try sending send_head again */
		if (previous == tcp_send_head(meta_sk)) {
			MPTCP_LOG("\t\treturning previous because (previous == tcp_send_head(meta_sk))  %p  %p\n",previous,tcp_send_head(meta_sk));
			//*send_head_again = true;
			return previous;
		}

		if(DESIRE_DELAY>0){
			MAX_LAG = lag.max_lag;
//			sysctl_mptcp_maxlag=lag.max_lag;
		}

		/* if necessary, catch up with the leading subflow */
		if ((lag.steps > 0) && (lag.steps > MAX_LAG)) {
			MPTCP_LOG("\t\treturning previous advanced by %d steps\n", (lag.steps - MAX_LAG));
			*monkeyhead_jumped = true;
			/* If the head and tail were synced before, if this skb gets sent, they will be un-synced.
			 * Initialize the tail to the place we're jumping from.  Don't set sk_data->monkeytail_synced.
			 * That will be set later if this skb is actually scheduled on the subflow.
			 * sk_data->monkeyhead_last_jump_seq  will be set later too, if this segment is actually sent. */
			if (sk_data->monkeytail_synced) {
				sk_data->monkeytail_skb = previous;
				sk_data->monkeytail_skb_end_seq = TCP_SKB_CB(sk_data->monkeytail_skb)->end_seq;
			}

			sk_data->monkeyhead_service_counter ++;
			sk_data->head_count ++;
			return monkeytail_advance_skb(previous, lag.steps - MAX_LAG);
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
	lag = monkeytail_steps_behind(queue, skb_peek_tail(queue), meta_sk,sub_sk,sk_data->leading_subsk_rate, sk_data->leading_subsk_rtt);
	MAX_LAG=lag.max_lag;
	/* Backtrack by the appropriate possible lag and re-send one of them. */
	i = 0;
	while (i < MAX_LAG && skb->prev != (const struct sk_buff *) queue) {
		i++;
		skb = skb->prev;
	}

	/* If we did not backtrack to the head of the queue, then the monkey tail is implicitly
	 * there now, and if this segment is sent we will be un-synced. */
	if (skb != skb_peek(queue)) {
		sk_data->monkeytail_skb = NULL;
		sk_data->monkeytail_skb_end_seq = TCP_SKB_CB(skb_peek(queue))->seq - 1;
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
	int flow_count;
	int max_cap;
	int max_rtt;
	int monkey_mode;
	struct monkeytailsched_sock_data *sk_data;

	flow_count=0;
	max_cap= 0;
	max_rtt= 0;
	monkey_mode =HEAD_MODE;
	u32 DESIRE_DELAY = sysctl_mptcp_desired_latency;

	if (!first_tp) {
		MPTCP_LOG("\tmonkeytail_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}


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
	if ((max_rtt/2+min_rtt) < DESIRE_DELAY){
			monkey_mode=TAIL_MODE;
		}else if ((min_rtt/2) < DESIRE_DELAY){
			monkey_mode=FOLLOW_MODE;
		}else{
			monkey_mode=HEAD_MODE;
	}
	sk_data = monkeytailsched_get_sock_data(selected_monkey);
	sk_data->monkey_mode = monkey_mode;
	sk_data->leading_subsk_rate=max_cap;
	sk_data->leading_subsk_rtt=max_rtt;
//	sk_data->leading_subsk_rtt=90000;
	MPTCP_LOG("sk %d mincapa %d maxcap %d min_rtt %d maxrtt %d mode %d \n",selected_monkey->inet_conn.icsk_inet.inet_saddr,min_cap,max_cap,min_rtt,max_rtt,monkey_mode );
	return selected_monkey;
}


/*
 * Two big dilemmas for this scheduler:
 *
 * - When there is a leading flow, how to keep the tail synced with the head?
 *   In this case when the head sends a packet, the tail has to advance too.
 *   When the head jumps ahead and the tail gets left behind, then sending
 *   on the head does not advance the tail.  But we need to watch for the
 *   tail catching upso we can put them back in sync.
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
static struct sk_buff *monkeytail_next_segment(struct sock *meta_sk,
					      int *reinject,
					      struct sock **subsk,
					      unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct monkeytailsched_cb_data *cb_data = monkeytailsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct tcp_sock *monkey_sf=NULL;
	struct sk_buff *skb;
	int active_valid_sks = -1;
//	u32 TAIL_SERVICE_INTERVAL = sysctl_mptcp_tail_service_interval;

	MPTCP_LOG("********************* monkeytail_next_segment *********************\n");
	//MPTCP_LOG("\tstarting with first_tp=%p\n",first_tp);

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
	    skb_queue_empty(&meta_sk->sk_write_queue)) {
		/* Nothing to send */
		MPTCP_LOG("\tmonkeytail_next_segment return NULL because skb_queue_empty()\n");
		return NULL;
	}

	/* First try reinjections */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk) {
			MPTCP_LOG("\tmonkeytail_next_segment return NULL because (!*subsk)\n");
			return NULL;
		}
		*reinject = 1;
		MPTCP_LOG("\tmonkeytail_next_segment return reinject sk_buff %p and sock %p\n", skb, *subsk);
		return skb;
	}

	/* Then try indistinctly redundant and normal skbs */

	if (!first_tp) {
		first_tp = mpcb->connection_list;
		//MPTCP_LOG("\tfirst_tp undefined.  setting first_tp = mpcb->connection_list=%p\n",first_tp);
	}

	/* still NULL (no subflow in connection_list?) */
	if (!first_tp) {
		MPTCP_LOG("\tmonkeytail_next_segment return NULL because (!first_tp)\n");
		return NULL;
	}

	tp = first_tp;

	*reinject = 0;
	active_valid_sks = monkeytailsched_get_active_valid_sks(meta_sk);
//	long largest_capacity=0L;
	do {
		struct monkeytailsched_sock_data *sk_data;
		bool packet_from_monkeytail;
		bool monkeyhead_jumped;
		MPTCP_LOG("    ******** monkeytail_next_segment trying sock %p ********\n", tp);

		/* Correct the skb pointers of the current subflow */
		sk_data = monkeytailsched_get_sock_data(tp);
		monkeytailsched_correct_skb_pointers(meta_sk, sk_data);

		skb = NULL;
		packet_from_monkeytail = false;
		//MPTCP_LOG("\ttry to get an sk_buff from the queue\n");

		// if the flow has higher capacity, don't be a monkey
		monkey_sf= get_selected_monkey(mpcb);
		MPTCP_LOG("\tChosen monkey %p\n",monkey_sf);

		if (!monkey_sf || tp != monkey_sf){
			skb =tcp_send_head(meta_sk);
			sk_data->queue_head_count++;
			packet_from_monkeytail = false;
		}else{
			MPTCP_LOG("\tmonkeytail_synced = %d   monkeytail_service_counter = %d\n", sk_data->monkeytail_synced, sk_data->monkeytail_service_counter);
			struct sk_buff *send_tail = skb_peek(&meta_sk->sk_write_queue);
			struct skb_mstamp now;
			skb_mstamp_get(&now);
			if (send_tail){
				MPTCP_LOG("\t QueueLen %d\n",skb_mstamp_us_delta(&now, &(send_tail->skb_mstamp)));
			}
			int rtt=tp->srtt_us>>3;
			if (sk_data->monkey_mode==FOLLOW_MODE && send_tail && skb_mstamp_us_delta(&now, &(send_tail->skb_mstamp)) > (sk_data->leading_subsk_rtt/2+rtt/2) ){
				sk_data->recover_mode=true;

			}else{
				sk_data->recover_mode=false;
				sk_data->recover_sent=false;
			}
			sk_data->recover_mode=false;

			if (sk_data->monkeytail_synced) {
				/* if monkeyhead and monkeytail are synced, just service the head */
				skb = monkeytail_next_skb_from_monkeyhead(&meta_sk->sk_write_queue, sk_data, meta_sk,tp, &monkeyhead_jumped);
				packet_from_monkeytail = false;
			} else {
				/* if they are not synced, we decide which to service based on a counter */
	//			if (sk_data->monkeytail_service_counter >= TAIL_SERVICE_INTERVAL) {!sk_data->monkeytail_skb && && (sk_data->monkey_mode==TAIL_MODE || (sk_data->recover_mode && !sk_data->recover_sent))
				if ( sk_data->monkey_mode==TAIL_MODE || (sk_data->recover_mode && !sk_data->recover_sent)) {
//				if ( sk_data->monkey_mode==TAIL_MODE){
					/* try to get a packet from the tail */
						skb = monkeytail_next_skb_from_monkeytail(&meta_sk->sk_write_queue, sk_data, meta_sk);
						sk_data->recover_sent=true;
//						MPTCP_LOG("\t tail %p skb %p lost_detected %d\n",send_tail,skb,skb_mstamp_us_delta(&now, &(send_tail->skb_mstamp)));
						packet_from_monkeytail = true;

				}
				/* if we failed to get one from the tail, we still need to try the head */
				if (!skb) {
					if (sk_data->monkey_mode==HEAD_MODE){
						sk_data->monkeyhead_service_counter=0;
						sk_data->queue_head_count ++;
						skb = tcp_send_head(meta_sk);
					}else{
						skb = monkeytail_next_skb_from_monkeyhead(&meta_sk->sk_write_queue, sk_data, meta_sk,tp, &monkeyhead_jumped);
					}
					packet_from_monkeytail = false;
				}
			}
			if (packet_from_monkeytail){
				sk_data->tail_count ++;
			}else{

			}

		}

		MPTCP_LOG("sk %d head %d tail %d queue_head %d gso %d\n",tp->inet_conn.icsk_inet.inet_saddr,sk_data->head_count, sk_data->tail_count, sk_data->queue_head_count, mptcp_sk_can_gso(meta_sk));
		MPTCP_LOG("\tmonkeytail_next_skb_from_queue returned %p\n", skb);
		MPTCP_LOG("\tmonkeytail_synced=%d  monkeyhead=%p  monkeytail=%p\n",sk_data->monkeytail_synced,sk_data->monkeyhead_skb,sk_data->monkeytail_skb);

		if (skb && monkeytailsched_use_subflow(meta_sk, active_valid_sks, tp, skb)) {
			MPTCP_LOG("\t\tmonkeytailsched_use_subflow is:\t\t\t\t\t\t\tTRUE!\n");
			if (packet_from_monkeytail) {
				MPTCP_LOG("\t\tpacket_from_monkeytail\n");
				/* here we /should/ check if this segment will catch us up to monkeyhead or the last jump point */
				sk_data->monkeytail_service_counter = 0;
				sk_data->monkeytail_skb = skb;
				sk_data->monkeytail_skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			} else {
				MPTCP_LOG("\t\tNOT packet_from_monkeytail\n");
				sk_data->monkeytail_service_counter++;
				if (monkeyhead_jumped) {
					MPTCP_LOG("\t\tmonkeyhead_jumped!\n");
					sk_data->monkeytail_synced = false;

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
			MPTCP_LOG("\tmonkeytail_next_segment return sk_buff %p and sock %p\n", skb, *subsk);
			return skb;
		} else {
			MPTCP_LOG("\tmonkeytail_next_segment skipping because !skb or !use_subflow is \t\t\tFALSE!");
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	MPTCP_LOG("\tmonkeytail_next_segment return NULL (end of function)\n");
	return NULL;
}


static void monkeytail_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct monkeytailsched_cb_data *cb_data = monkeytailsched_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	 * the pointer
	 */
	if (cb_data->next_subflow == tp)
		cb_data->next_subflow = tp->mptcp->next;
}

static struct mptcp_sched_ops mptcp_sched_monkeytail = {
	.get_subflow = monkeytail_get_subflow,
	.next_segment = monkeytail_next_segment,
	.release = monkeytail_release,
	.name = "monkeytail",
	.owner = THIS_MODULE,
};

static int __init monkeytail_register(void)
{
	MPTCP_LOG("monkeytail_register\n");
	BUILD_BUG_ON(sizeof(struct monkeytailsched_sock_data) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct monkeytailsched_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_monkeytail))
		return -1;

	return 0;
}

static void monkeytail_unregister(void)
{
	MPTCP_LOG("monkeytail_unregister\n");
	mptcp_unregister_scheduler(&mptcp_sched_monkeytail);
}

module_init(monkeytail_register);
module_exit(monkeytail_unregister);

MODULE_AUTHOR("Brenton Walker");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MONKEYTAIL REDUNDANT MPTCP");
MODULE_VERSION("0.90");
