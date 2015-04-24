#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"

#define ACK_LEN 8
#define PKG_MIN_LEN 12
#define PKG_MAX_LEN 512
#define MAX_DATA_LEN 500

#define O_READ_EOF (1<<0) /* EOF from other side received */
#define M_READ_EOF (1<<1) /* EOF from my side received */
#define ALL_PKT_ACK (1<<2) /* All packets we sent were acknowledget */
#define WROTE_ALL (1<<3) /* We have written everything to the stdout */

void handle_data_packet(rel_t *r, packet_t *pkt);
void send_ackpkt(rel_t *r, uint32_t ackno);

struct reliable_state {
	rel_t *next;			/* Linked list for traversing all connections */
	rel_t **prev;

	conn_t *c;			/* This is the connection object */

	/* Add your own data fields below this */

	uint32_t ackno; /* We received all packets up to this (not including) number */
	uint32_t seqno; /* the next package we send has this number */
	uint32_t larno; /* other side received all packages up to this number */

	packet_t **recv_window; /* buffer for received packages */	
	packet_t **out_window; /* buffer for outgoing packages */	
	uint32_t window_size;

	uint32_t recv_wrt_bytes; /* indicates the number of bytes of the current pkt we already wrote  to our buffer */
	uint32_t out_wrt_bytes; /* indicates the number of bytes of the current pkt we already wrote to the next packet */
	char terminate_state; /**/

	char s_wait; /* not zero, if we cant send at the moment */
};
rel_t *rel_list;


/* Creates a new reliable protocol session, returns NULL on failure.
 * ss is always NULL */
rel_t * rel_create (conn_t *c, const struct sockaddr_storage *ss,
		const struct config_common *cc)
{
	rel_t *r;

	r = xmalloc (sizeof (*r));
	memset (r, 0, sizeof (*r));

	if (!c) {
		c = conn_create (r, ss);
		if (!c) {
			free (r);
			return NULL;
		}
	}

	r->c = c;
	r->next = rel_list;
	r->prev = &rel_list;
	if (rel_list){
		rel_list->prev = &r->next;
	}
	rel_list = r;

	/* Do any other initialization you need here */

	r->ackno = 1;
	r->seqno = 1;
	r->larno = 1;
	r->recv_wrt_bytes = 0;
	r->out_wrt_bytes = 0;
	r->window_size = cc->window;
	r->recv_window = xmalloc(cc->window * sizeof(packet_t *));
	memset(r->recv_window, 0, cc->window * sizeof(packet_t *));
	
	r->out_window = xmalloc(cc->window * sizeof(packet_t *));
	memset(r->out_window, 0, cc->window * sizeof(packet_t *));

	r->terminate_state = 0 | WROTE_ALL | ALL_PKT_ACK;
	r->s_wait = 0;
	
	return r;
}

void rel_destroy (rel_t *r)
{
	if (r->next)
		r->next->prev = r->prev;
	*r->prev = r->next;
	conn_destroy (r->c);

	/* Free any other allocated memory here */
	free(r->recv_window);
	free(r->out_window);
}

/**
 * 
 */
void rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
	uint16_t checksum = pkt->cksum;
	pkt->cksum = 0;
	uint16_t length = ntohs(pkt->len);
	if(!cksum(pkt, length) == checksum)
	{
		fprintf(stderr,
				"Received package with invalid checksum.\n");	
		return;
	}
	pkt->len = length;
	pkt->ackno = ntohl(pkt->ackno);
	pkt->seqno = ntohl(pkt->seqno);
	if(pkt->len != n)
	{
		fprintf(stderr,
				"Received package with invalid length. Expected %d got %d\n",
				pkt->len, n);	
		return;
	}
	/* 
	 * update larno 
	 */
	if(pkt->ackno > r->larno)
	{
		for(int i = r->larno; i < pkt->ackno; i++)
		{
			// free all packages that are received
			packet_t *p = r->out_window[i % r->window_size];
			if(p != NULL)
			{
				// free(p); // TODO
				fprintf(stderr, "Freed %d\n", p->seqno);
				r->out_window[i % r->window_size] = NULL;
			}
		}
		r->larno = pkt->ackno;
		if(r->s_wait)
		{
			r->s_wait = 0;
			rel_read(r); // TODO pretty
		}
	}
	if(pkt->len == ACK_LEN)
	{
		/* Nothing to do here */
		return;
	}
	assert(pkt->len >= PKG_MIN_LEN);
	assert(pkt->len <= PKG_MAX_LEN);
	pkt->len -= PKG_MIN_LEN;
	handle_data_packet(r, pkt);
}

void send_ackpkt(rel_t *r, uint32_t ackno)
{
		packet_t *p = (packet_t *)xmalloc(sizeof(packet_t));
		p->len = htons(ACK_LEN);
		p->ackno = htonl(ackno);
		p->cksum = cksum(p, ACK_LEN);
		int res = conn_sendpkt(r->c, p, ACK_LEN); 
		assert(res == ACK_LEN);
	//	free(p); // TODO
}

void handle_data_packet(rel_t *r, packet_t *pkt)
{
	if(pkt->seqno < r->ackno)
	{
		send_ackpkt(r, r->ackno);
		return;
	}
	if(pkt->seqno < r->ackno + r->window_size)
	{
		packet_t *old = r->recv_window[pkt->seqno % r->window_size];
	   	if(old != NULL)
		{
			//free(old);
		}
		r->recv_window[pkt->seqno % r->window_size] = pkt;
		rel_output(r);
	}
	else
	{
		fprintf(stderr,
				"Received package out of window: Ackno: %d Pkgno: %d WindowSize: %d\n",
				r->ackno, pkt->seqno, r->window_size);
	}
}

void send_packet(rel_t *r, packet_t *pkt)
{
	// checking
	assert(pkt != NULL);
	
	pkt->len += PKG_MIN_LEN;
	assert(pkt->len >= PKG_MIN_LEN);
	assert(pkt->len <= PKG_MAX_LEN);
	uint16_t length = pkt->len;
	
	if(pkt->seqno == 0)
	{
		assert(r->seqno < r->larno + r->window_size);
		pkt->seqno = r->seqno;
		r->seqno++;
	}
	else
	{
		assert(pkt->seqno < r->larno + r->window_size);
	}
	// encode for network	
	pkt->seqno = htonl(pkt->seqno);
	pkt->len = htons(pkt->len);
	pkt->ackno = htonl(pkt->ackno);
	pkt->cksum = 0;
	pkt->cksum = cksum(pkt, length);
	int res = conn_sendpkt(r->c, pkt, length);
	assert(res == length);

	// decode for host
	pkt->seqno = ntohl(pkt->seqno);
	pkt->len = ntohs(pkt->len);
	pkt->ackno = ntohl(pkt->ackno);

	r->out_window[pkt->seqno % r->window_size] = pkt;
}

/*
 * 
 */
void rel_read (rel_t *s)
{
	if(s->s_wait || s->seqno >= s->larno + s->window_size)
	{
		fprintf(stderr, 
				"Our ending window is full!\n");
		s->s_wait = 1;
		return;
	}
	packet_t *waiting_pkt = s->out_window[s->larno % s->window_size];
	if(waiting_pkt != NULL && waiting_pkt->len < MAX_DATA_LEN)
	{
		fprintf(stderr, "I did not send a new package, because the waiting one is not full!\n");
		s->s_wait = 1;
		return;
	}
	packet_t *akt_packet = s->out_window[(s->seqno - 1) % s->window_size];
	if(akt_packet != NULL && akt_packet->len < MAX_DATA_LEN)
	{
		fprintf(stderr, "I did not send a new package, because the current one is not full!\n");
		s->s_wait = 1;
		return;
	}
	packet_t *pkt = (packet_t *)xmalloc(sizeof(packet_t));

	int read = conn_input(s->c, pkt->data, MAX_DATA_LEN);
	// -1: EOF / ERROR
	if(read == -1)
	{
		fprintf(stderr,
				"Error or EOF on reading\n");
		pkt->len = 0;
		send_packet(s, pkt);
		s->terminate_state |= M_READ_EOF;
	}
	else if(read == 0)
	{
		// :-(
		fprintf(stderr,
				"[DEBUG] I was too greedy and had to free the xmallocated packet again :-(\n");
		free(pkt);
	}
	else
	{
		pkt->len = read; // TODO send/read moore
		send_packet(s, pkt);
	}
}

/*
 *
 */
void rel_output (rel_t *r)
{
	int can_write = 1;
	while(can_write)
	{
		packet_t *pkt = r->recv_window[r->ackno % r->window_size];
		if(pkt == NULL)
		{
			return;
		}
		if(pkt->len == 0)
		{
			fprintf(stderr, "Received EOF\n");
			r->terminate_state |= O_READ_EOF;
			return;
		}
		assert(pkt->len > r->recv_wrt_bytes);
		int wrote = conn_output(r->c, pkt->data + r->recv_wrt_bytes,
				pkt->len - r->recv_wrt_bytes);
		if(wrote  + r->recv_wrt_bytes == pkt->len)
		{
			r->recv_wrt_bytes = 0;
			r->recv_window[r->ackno % r->window_size] = NULL;
			r->ackno++;
			send_ackpkt(r, r->ackno);
			r->terminate_state |= WROTE_ALL;
		}
		else
		{
			assert(pkt->len > wrote + r->recv_wrt_bytes);
			r->recv_wrt_bytes += wrote;
			can_write = 0;
			r->terminate_state &= ~WROTE_ALL;
		}
	}
}

void rel_timer ()
{
	/* Retransmit any packets that need to be retransmitted */

}
