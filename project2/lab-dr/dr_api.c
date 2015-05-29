/* Filename: dr_api.c */

/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "dr_api.h"
#include "rmutex.h"

#include <assert.h>

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 20
#define RIP_GARBAGE_SEC 20

void print_interface(lvns_interface_t iface);
void advertise();
void dump_rip_table();
void print_ip(char*, int);
/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
	uint16_t addr_family;
	uint16_t pad;           /* just put zero in this field */
	uint32_t ip;
	uint32_t subnet_mask;
	uint32_t next_hop;
	uint32_t metric;
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
	char        command;
	char        version;
	uint16_t    pad;        /* just put zero in this field */
	rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
	uint32_t subnet;        /* destination subnet which this route is for */
	uint32_t mask;          /* mask associated with this route */
	uint32_t next_hop_ip;   /* next hop on on this route */
	uint32_t outgoing_intf; /* interface to use to send packets on this route */
	uint32_t cost;
	uint32_t old_interface_cost;
	struct timeval last_updated;

	int is_garbage; /* boolean which notes whether this entry is garbage */

	struct route_t* next;  /* pointer to the next route in a linked-list */
} route_t;

void dump_route(route_t* node);

/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/**
 * Sends specified dynamic routing payload.
 * @param dst_ip   The ultimate destination of the packet.
 * @param next_hop_ip  The IP of the next hop (either a router or the final dst).
 * @param outgoing_intf  Index of the interface to send the packet from.
 * @param payload  This will be sent as the payload of the DR packet.  The caller 
 * is reponsible for managing the memory associated with buf
 * (e.g. this function will NOT free buf).
 * @param len The number of bytes in the DR payload.
 **/
static void (*dr_send_payload)(uint32_t dst_ip,
		uint32_t next_hop_ip,
		uint32_t outgoing_intf,
		char* /* borrowed */,
		unsigned);


/* internal functions */

/* internal lock-safe methods for the students to implement */
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
		char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
		int state_changed,
		int cost_changed);

/**
 * This simple method is the entry point to a thread which will periodically
 * make a callback to your dr_handle_periodic method.
 **/
static void* periodic_callback_manager_main(void* nil) {
	struct timespec timeout;

	timeout.tv_sec = secs_to_sleep_between_callbacks;
	timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
	while(1) {
		nanosleep(&timeout, NULL);
		dr_handle_periodic();
	}

	return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
	next_hop_t hop;
	rmutex_lock(&coarse_lock);
	hop = safe_dr_get_next_hop(ip);
	rmutex_unlock(&coarse_lock);
	return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
	rmutex_lock(&coarse_lock);
	safe_dr_handle_packet(ip, intf, buf, len);
	rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
	rmutex_lock(&coarse_lock);
	safe_dr_handle_periodic();
	rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
	rmutex_lock(&coarse_lock);
	safe_dr_interface_changed(intf, state_changed, cost_changed);
	rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */
route_t *route_list;

void dr_init(unsigned (*func_dr_interface_count)(),
		lvns_interface_t (*func_dr_get_interface)(unsigned index),
		void (*func_dr_send_payload)(uint32_t dst_ip,
			uint32_t next_hop_ip,
			uint32_t outgoing_intf,
			char* /* borrowed */,
			unsigned)) {
	pthread_t tid;

	/* save the functions the DR is providing for us */
	dr_interface_count = func_dr_interface_count;
	dr_get_interface = func_dr_get_interface;
	dr_send_payload = func_dr_send_payload;

	/* initialize the recursive mutex */
	rmutex_init(&coarse_lock);

	/* initialize the amount of time we want between callbacks */
	secs_to_sleep_between_callbacks = RIP_ADVERT_INTERVAL_SEC; // 10 because we need to update ever 10/20 seconds
	nanosecs_to_sleep_between_callbacks = 0;

	/* start a new thread to provide the periodic callbacks */
	if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
		fprintf(stderr, "pthread_create failed in dr_initn");
		exit(1);
	}

	/* do initialization of your own data structures here */

	int c_interface = dr_interface_count();
	for(int i = 0; i < c_interface; i++)
	{ // TODO make make an insert route function
		// TODO check interfaces
		lvns_interface_t iface = dr_get_interface(i);
		print_interface(iface); 
		route_t* route = (route_t *)malloc(sizeof(route_t));
		route->subnet = iface.ip & iface.subnet_mask;
		route->mask = iface.subnet_mask;
		route->next_hop_ip = 0;
		route->outgoing_intf = i;
		route->cost = iface.cost;
		route->old_interface_cost = iface.cost;
		/* gettimeofday(&route->last_updated, NULL); */
		(&route->last_updated)->tv_sec = 0xFFFFFFFF; // To prevent from beeing deleted
		route->is_garbage = 0;
		route->next = route_list;
		route_list = route;
		fprintf(stderr, "Added (interface) route: \n");
		dump_route(route);
	}

	advertise();
}

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
	print_ip("Next hop called", ip);
	next_hop_t hop;

	hop.interface = 0;
	hop.dst_ip = 0;

	/* determine the next hop in order to get to ip */
	route_t* node = route_list;
	
	uint32_t longest_mask = 0;

	while(node != NULL)
	{
		if(!node->is_garbage && node->cost != INFINITY)
		{
			if( (ip & node->mask) == (node->subnet & node->mask))
			{
				if(ntohl(node->mask) > longest_mask)
				{
					ntohl(longest_mask = node->mask);
					hop.interface = node->outgoing_intf;
					hop.dst_ip = node->next_hop_ip;
				}
			}
		}
		node = node->next;
	}
	// TODO check if found
	if(longest_mask == 0)
	{
		dump_rip_table();
		hop.dst_ip = 0xFFFFFFFF;
		fprintf(stderr, "ERROR: no route found :-(\n");
	}
	else
	{
		fprintf(stderr, "DEBUG: found route <3\n");
	}
	return hop;
}

void safe_dr_handle_packet(uint32_t ip, unsigned intf,
		char* buf /* borrowed */, unsigned len) {
	/* handle the dynamic routing payload in the buf buffer */
	if(len < sizeof(rip_header_t))
	{
		fprintf(stderr, "ERROR: Packet too small! %d\n", len);
		return;
	}
	rip_header_t* header = (rip_header_t*)buf;
	if(header->command != RIP_COMMAND_RESPONSE)
	{
		fprintf(stderr, "ERROR: Invalid command\n");
		return;
	}
	if(header->version != RIP_VERSION)
	{
		fprintf(stderr, "ERROR: Invalid RIP_VERSION\n");
		return;
	}
	if(ip == 0 || ip == -1)
	{
		fprintf(stderr, "DEBUG: Unicast -> drop\n");
		return;
	}
	fprintf(stderr, "INFO: Handle packet\n");
	int changed = 0;
	lvns_interface_t iface = dr_get_interface(intf);
	assert((len - sizeof(rip_header_t)) % sizeof(rip_entry_t) == 0);
	uint32_t entries_length = (len - sizeof(rip_header_t)) / sizeof(rip_entry_t);
	for(uint32_t i = 0; i < entries_length; i++)
	{
		rip_entry_t entry = header->entries[i];
		entry.metric += iface.cost; 
		route_t* node = route_list;
		while(node != NULL)
		{
			if((node->subnet == entry.ip) && (node->mask == entry.subnet_mask))
			{
				gettimeofday(&node->last_updated, NULL);
				if((node->cost > entry.metric) || node->is_garbage)
				{ // found a better route
					node->cost = entry.metric;
					node->outgoing_intf = intf;
					node->next_hop_ip = ip;
					node->cost = entry.metric;
					node->old_interface_cost = iface.cost;
					gettimeofday(&node->last_updated, NULL);
					node->is_garbage = 0;
					fprintf(stderr, "Updated route: \n");
					dump_route(node);
					changed = 1;
				}
				break; // we handled the entry
			}
			node = node->next;
		}
		if(node == NULL && entry.metric < INFINITY)
		{ // we did not find it, so we insert it
			route_t* route = (route_t *)malloc(sizeof(route_t));
			route->subnet = entry.ip;
			assert(route->subnet != 0);
			route->mask = entry.subnet_mask;
			route->next_hop_ip = entry.next_hop; // TODO correcnt?
			route->outgoing_intf = i;
			route->next_hop_ip = ip;
			route->cost = entry.metric;
			route->old_interface_cost = iface.cost;
			gettimeofday(&route->last_updated, NULL);
			route->is_garbage = 0;
			route->next = route_list;
			route_list = route;
			fprintf(stderr, "Inserted route: \n");
			dump_route(route);
			changed = 1;
		}
	}

	if(changed)
	{
		advertise();
	}
}

void safe_dr_handle_periodic() {
	/* handle periodic tasks for dynamic routing here */
	advertise();
}

static void safe_dr_interface_changed(unsigned intf,
		int state_changed,
		int cost_changed) {
	/* handle an interface going down or being brought up */
	fprintf(stderr, "Interface changed: Interface: %d state: %d cost: %d\n", intf, state_changed, cost_changed);
	int changed = 0;
	route_t *route_node = route_list;
	lvns_interface_t iface = dr_get_interface(intf);	
	while(route_node != NULL)
	{
		if(route_node->outgoing_intf == intf)
		{
			if(!iface.enabled)
			{
				route_node->is_garbage = 1;
			}
			if(cost_changed)
			{
				route_node->cost = route_node->cost - route_node->old_interface_cost + iface.cost;
				assert(route_node->cost < INFINITY);
				route_node->old_interface_cost = iface.cost;
			}
			changed = 1;
		}
		route_node = route_node->next;
	}
	if(changed)
	{
		advertise();
	}
}

/* definition of internal functions */

void print_ip(char* label, int ip)
{
	ip = ntohl(ip);
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;	
	fprintf(stderr, "%s: %d.%d.%d.%d\n",label, bytes[3], bytes[2], bytes[1], bytes[0]);
}

void print_interface(lvns_interface_t iface){
	fprintf(stderr, "*** Interface ***\n");
	print_ip("IP", iface.ip);
	print_ip("subnetmask", iface.subnet_mask);
	fprintf(stderr, "Enabled: %d\nCost: %d\n", iface.enabled, iface.cost);
}

void dump_route(route_t* node)
{
		fprintf(stderr, "*ROUTE*\n");
		print_ip("subnet", (node->subnet));
		print_ip("mask", (node->mask));
		print_ip("next_hop_ip", (node->next_hop_ip));
		fprintf(stderr, "outgoing intf: %d\n", node->outgoing_intf);
		fprintf(stderr, "cost: %d\n", node->cost);
		fprintf(stderr, "is_garbage: %d\n", node->is_garbage);
}

void dump_rip_table()
{
	fprintf(stderr, "***START TABLE DMP***\n");
	route_t* node = route_list;
	while(node != NULL)
	{
		dump_route(node);
		node = node->next;
	}
}

void advertise()
{
	fprintf(stderr, "Start advertising\n");
	uint32_t routes_length = 0;
	route_t *route_node = route_list;
	route_t *prev_node = NULL;
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	
	while(route_node != NULL)
	{
		if(route_node->last_updated.tv_sec  + RIP_GARBAGE_SEC <= current_time.tv_sec)
		{
			route_node->is_garbage = 1;
			fprintf(stderr, "DEBUG: Route is now garbage\n");
			dump_route(route_node);
		}
		if(route_node->is_garbage)
		{ // remove garbage
			if(prev_node == NULL)
			{
				route_list = route_node->next;
			}
			else
			{
				prev_node->next = route_node->next;
			}
			free(route_node);
			route_node = prev_node->next;
		}
		else
		{
			routes_length++;
			prev_node = route_node;
			route_node = route_node->next;
		}
	}
	uint32_t buffer_size = sizeof(rip_header_t) + routes_length * sizeof(rip_entry_t);
	rip_header_t *rip_payload = (rip_header_t *)malloc(buffer_size);
	rip_payload->command = RIP_COMMAND_RESPONSE;
	rip_payload->version = RIP_VERSION;
	rip_payload->pad = 0;
	

	// because poisoned reverse we do a loop over all interfaces
	uint32_t iface_length = dr_interface_count(); 
	for(uint32_t j = 0; j < iface_length; j++)
	{
		uint32_t i = 0;
		route_node = route_list;	
		while(route_node != NULL)
		{
			assert(i <= routes_length);
			if(!route_node->is_garbage)
			{
				rip_entry_t *entry = &rip_payload->entries[i];	
				entry->addr_family = htons(AF_INET);
				entry->pad = 0;
				entry->ip = route_node->subnet;
				assert(entry->ip != 0);
				entry->subnet_mask = route_node->mask;
				entry->next_hop = route_node->next_hop_ip;
				if(j == route_node->outgoing_intf){
					entry->metric = INFINITY; // Split Horizon with Poisoned Reverse
				}
				else
				{
					entry->metric = route_node->cost;
				}
				i++;
			}
			route_node = route_node->next;
		}
		assert(i == routes_length);
		dr_send_payload(RIP_IP, RIP_IP, j, (char *)rip_payload, buffer_size);
	}
	free(rip_payload);
	dump_rip_table();
}
