/*
 * iot_ticket.c
 *
 *  Created on: 07.05.2018
 *      Author: markus
 */

#include "iot_ticket.h"
#include "or.h"

#include "aes.h"
#include "channel.h"
#include "crypto.h"
#include "main.h"
#include "aes.h"
#include "relay.h"
#include "circuitlist.h"
#include "torlog.h"
#include "connection.h"
#include "container.h"
#include "channeltls.h"
#include "connection_or.h"
#include "config.h"

#include "nodelist.h"
#include "routerset.h"

#include "circuituse.h"
#include "circuitbuild.h"

#include "hs_circuit.h"

#include "connection_edge.h"

const uint8_t iot_key[] =
{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
const uint8_t iot_mac_key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
		14, 15 };

const uint8_t iot_iv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

const char iot_id[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

STATIC smartlist_t *splitted_circuits = NULL;
STATIC smartlist_t *connected_iot_dev = NULL;

uint32_t iot_circ_id = 17;

#define SPLITPOINT_BEFORE_HS(circ) circ->cpath->prev->prev->prev->prev
#define SPLITPOINT(circ) SPLITPOINT_BEFORE_HS(circ)->prev

static uint8_t iot_relay_to_device(const uint8_t *target_id, size_t length,
		const uint8_t *payload, uint8_t command);

int
iot_circ_launch_entry_point(entry_connection_t *conn, uint8_t handover) {
	int circ_flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
	origin_circuit_t *circ;
	extend_info_t *info;

	const node_t *their_entry;
	const node_t *our_entry;

	smartlist_t *list;
	list = smartlist_new();
	routerset_get_all_nodes(list, get_options()->IoTEntryNodes, NULL, 0);
	their_entry = smartlist_get(list, 0);

	if (!their_entry) {
		log_warn(LD_GENERAL, "Tried to launch circuit to entry point we could not find.");
		return -1;
	}

	info = extend_info_from_node(their_entry, 0);

	if (handover) {
		our_entry = smartlist_get(list, 1);

		if (!our_entry) {
			log_warn(LD_GENERAL, "We could not find our entry");
			return -1;
		}

		info->iot_circ_info.after = 3;
		info->iot_circ_info.split = our_entry;
		info->iot_circ_info.is_set = 1;
	}

	smartlist_free(list);

	log_debug(LD_GENERAL, "Launching circuit to IoT entry node.");
	circ = circuit_launch_by_extend_info((handover ? CIRCUIT_PURPOSE_ENTRY_IOT_HANDOVER : CIRCUIT_PURPOSE_ENTRY_IOT),
			info, circ_flags);

	if (circ==NULL) {
		extend_info_free(info);
		return 0;
	}

	circ->iot_entry_conn = conn;

	return 0;
}

static void
iot_fast_ticket_send(origin_circuit_t *circ) {
	iot_relay_fast_ticket_t *msg;
	aes_cnt_cipher_t *encrypt;
	crypt_path_t *cpath = NULL;
	uint8_t is_service_side;

	tor_assert(circ->base_.purpose == CIRCUIT_PURPOSE_ENTRY_IOT ||
			circ->base_.purpose == CIRCUIT_PURPOSE_ENTRY_IOT_HANDOVER);
	log_info(LD_REND, "Sending a FAST_TICKET cell");

	// Create FAST TICKET
	msg = tor_malloc(sizeof(iot_relay_fast_ticket_t));

	// Fill nonce
	crypto_rand((char *) msg->ticket.nonce, IOT_TICKET_NONCE_LEN);

	// Fill cookies
	crypto_rand((char *) &msg->cookie, 4);
	memcpy(&msg->ticket.cookie, &msg->cookie, 4);
	log_info(LD_GENERAL, "Chosen cookie: 0x%08x  0x%08x", msg->ticket.cookie,
			msg->cookie);

	// Generate E2E Crypto into ticket and initilize it at the client
	crypto_rand((char *) msg->ticket.hs_ntor_key, HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

	/* Setup the cpath */
	is_service_side = 0;
	cpath = tor_malloc_zero(sizeof(crypt_path_t));
	cpath->magic = CRYPT_PATH_MAGIC;

	if (circuit_init_cpath_crypto(cpath, (char *) msg->ticket.hs_ntor_key, HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN,
			is_service_side, 1) < 0) {
		tor_free(cpath);
		log_warn(LD_GENERAL, "Could not initialize cpath crypto.");
	}

	//Compute HMAC we expect in FAST_TICKET_RELAYED2 cell
	crypto_hmac_sha256((char *) circ->iot_expect_hmac, (char *) iot_mac_key, DIGEST256_LEN, (char*) msg->ticket.hs_ntor_key,
				HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

	//Encrypt ticket
	encrypt = aes_new_cipher(iot_key, msg->ticket.nonce, 128);
	aes_crypt_inplace(encrypt, ((char*) &msg->ticket + IOT_TICKET_NONCE_LEN),
			sizeof(iot_fast_ticket_t) - DIGEST256_LEN - IOT_TICKET_NONCE_LEN);
	aes_cipher_free(encrypt);

	//Set ID of IoT device
	memcpy(msg->iot_id, iot_id, IOT_ID_LEN);

	//Compute MAC
	crypto_hmac_sha256((char*) (msg->ticket.mac), (char*) iot_mac_key, 16,
			(char*) &(msg->ticket), sizeof(iot_fast_ticket_t) - DIGEST256_LEN);

	log_debug(LD_GENERAL, "Sending fast ticket");

	if (relay_send_command_from_edge(0, TO_CIRCUIT(circ),
			RELAY_COMMAND_FAST_TICKET1,
			(const char*) msg,
			sizeof(iot_relay_fast_ticket_t),
			circ->cpath->prev)<0) {
		/* circ is already marked for close */
		log_warn(LD_GENERAL, "Couldn't send FAST_TICKET cell");
	}

	finalize_rend_circuit(circ, cpath, is_service_side);
	link_apconn_to_circ(circ->iot_entry_conn, circ, cpath);
}

void
iot_client_entry_handover_circuit_has_opened(origin_circuit_t *circ) {
	iot_fast_ticket_send(circ); // Send ticket to our serving IoT device
	iot_ticket_send(circ, IOT_TICKET_TYPE_CLIENT); // Send ticket to our client IoT device
}

int
iot_client_entry_circuit_has_opened(origin_circuit_t *circ) {
	iot_fast_ticket_send(circ);

	// Lets wait for the FAST_TICKET_RELAYED2 message
	TO_CONN(ENTRY_TO_EDGE_CONN(circ->iot_entry_conn))->state = AP_CONN_STATE_IOT_WAIT;

	return 0;
}

static or_connection_t *iot_find_iot_device(const uint8_t *target_id) {
	if (connected_iot_dev) {
		log_info(LD_GENERAL, "Looking for connected IoT device:");
		SMARTLIST_FOREACH_BEGIN(connected_iot_dev, or_connection_t *, c) {
			log_debug(LD_GENERAL, "Check %p", c);
			if (!memcmp(c->iot_id, target_id, IOT_ID_LEN)) {
				log_info(LD_GENERAL, "FOUND!");
				return c;
				break;
			}
			log_info(LD_GENERAL, "DIDNT MATCH");
		}SMARTLIST_FOREACH_END(c);
	} else {
		log_warn(LD_GENERAL,
				"Got a ticket but there never was a IoT device connected.");
		return 0;
	}
	return 0;
}

void iot_process_relay_fast_ticket(circuit_t *circ, size_t length,
		const uint8_t *payload) {
	struct timespec recv_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &recv_monotonic);

	iot_relay_fast_ticket_t *msg = (iot_relay_fast_ticket_t*) payload;

	tor_assert(length == sizeof(iot_relay_fast_ticket_t));

	log_info(LD_GENERAL, "Got IoT fast ticket with IoT id of size %ld.",
			sizeof(iot_relay_fast_ticket_t));

    or_connection_t *conn = iot_find_iot_device(msg->iot_id);

    if (!conn)
    	return;

    circuit_set_n_circid_chan(circ, iot_circ_id,
    		TLS_CHAN_TO_BASE(conn->chan));

    iot_circ_id++;

    circ->state = CIRCUIT_STATE_OPEN;

    var_cell_t *cell;

    cell = var_cell_new(sizeof(iot_ticket_t));

    cell->circ_id = iot_circ_id;
    cell->command = CELL_IOT_FAST_TICKET;
    cell->cell_num = TLS_CHAN_TO_BASE(conn->chan)->cell_num_out;
    TLS_CHAN_TO_BASE(conn->chan)->cell_num_out++;
    memcpy(cell->payload, payload, length);

    connection_or_write_var_cell_to_buf(cell, conn);

    struct timespec fwd_monotonic;
    clock_gettime(CLOCK_MONOTONIC, &fwd_monotonic);

	log_notice(LD_GENERAL, "RECVTICKET:%lus%luns", recv_monotonic.tv_sec,
			recv_monotonic.tv_nsec);

    log_notice(LD_GENERAL, "FWDTICKET:%lus%luns", fwd_monotonic.tv_sec,
    		fwd_monotonic.tv_nsec);
}

int iot_set_circ_info(const hs_service_t *hs, iot_circ_info_t *info) {
	(void) hs;

	info->after = 3;

	const node_t *entry;

	smartlist_t *list;
	list = smartlist_new();
	routerset_get_all_nodes(list, get_options()->IoTEntryNodes, NULL, 0);
	entry = smartlist_get(list, 2);
	smartlist_free(list);

	info->split = entry;

	if (!info->split) {
		return -1;
	} else {
		return 1;
	}
}

static void iot_ticket_set_relay_crypto(iot_crypto_aes_relay_t *iot_crypto,
		crypt_path_t *relay) {
	iot_crypto->b.crypted_bytes = htons(relay->b_crypted_bytes);
	iot_crypto->f.crypted_bytes = htons(relay->f_crypted_bytes);

	memcpy(&iot_crypto->b.aes_key, relay->b_aesctrkey, CIPHER_KEY_LEN);
	memcpy(&iot_crypto->f.aes_key, relay->f_aesctrkey, CIPHER_KEY_LEN);

	log_info(LD_GENERAL,
			"Forward key starts with %02x, backward key starts with %02x.",
			relay->f_aesctrkey[0], relay->b_aesctrkey[0]);
}

static inline uint64_t as_nanoseconds(struct timespec* ts) {
	return ts->tv_sec * (uint64_t) 1000000000L + ts->tv_nsec;
}

void iot_ticket_send(origin_circuit_t *circ, uint8_t type) {
	iot_relay_ticket_t *msg;
	crypt_path_t *split_point;
	aes_cnt_cipher_t *encrypt;

	tor_assert(circ);

	struct timespec send_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &send_monotonic);

	log_info(LD_REND, "Sending ticket.");

	//Choose split point such that we have 4 relays left + HS
	split_point = SPLITPOINT(circ);

	msg = tor_malloc(sizeof(iot_relay_ticket_t));

	// Fill nonce
	crypto_rand((char *) msg->ticket.nonce, IOT_TICKET_NONCE_LEN);

	// Fill cookies
	crypto_rand((char *) &msg->cookie, 4);
	memcpy(&msg->ticket.cookie, &msg->cookie, 4);
	log_info(LD_GENERAL, "Chosen cookie: 0x%08x  0x%08x", msg->ticket.cookie,
			msg->cookie);

	msg->ticket.type = type;

	// Set key information in ticket
	iot_ticket_set_relay_crypto(&msg->ticket.entry, split_point);
	// Split point is receiver of our ticket. Add payload size.
	msg->ticket.entry.f.crypted_bytes = htons(
			ntohs(msg->ticket.entry.f.crypted_bytes) + CELL_PAYLOAD_SIZE);

	iot_ticket_set_relay_crypto(&msg->ticket.relay1, split_point->next);
	iot_ticket_set_relay_crypto(&msg->ticket.relay2, split_point->next->next);
	iot_ticket_set_relay_crypto(&msg->ticket.rend,
			split_point->next->next->next);

	//Set init digest for rend (forward)
	memcpy(&msg->ticket.f_rend_init_digest, split_point->next->next->next->f_init_digest, DIGEST_LEN);

	//Set HS material
	memcpy(&msg->ticket.hs_ntor_key,
			split_point->next->next->next->next->hs_ntor_key,
			HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

	//Set Rend Info
	memcpy(msg->ticket.rend_info, circ->iot_rend_info, HSv3_REND_INFO);

	//Encrypt ticket
	encrypt = aes_new_cipher(iot_key, msg->ticket.nonce, 128);
	aes_crypt_inplace(encrypt, ((char*) &msg->ticket + IOT_TICKET_NONCE_LEN),
			sizeof(iot_ticket_t) - DIGEST256_LEN - IOT_TICKET_NONCE_LEN);
	aes_cipher_free(encrypt);

	//Set ID of IoT device
	memcpy(msg->iot_id, iot_id, IOT_ID_LEN);

	//Compute MAC
	crypto_hmac_sha256((char*) (msg->ticket.mac), (char*) iot_mac_key, 16,
			(char*) &(msg->ticket), sizeof(iot_ticket_t) - DIGEST256_LEN);

	log_info(LD_GENERAL, "Sending ticket to %s",
			split_point->extend_info->nickname);

	//Send it!
	relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_TICKET1,
			(const char* ) msg, sizeof(iot_relay_ticket_t), split_point);

	struct timespec sent_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &sent_monotonic);

	//New version: SP closes the circuit
	//circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);

	log_notice(LD_GENERAL, "SENDTICKET:%lus%luns", send_monotonic.tv_sec,
			send_monotonic.tv_nsec);
	log_notice(LD_GENERAL, "SENTTICKET:%lus%luns", sent_monotonic.tv_sec,
			sent_monotonic.tv_nsec);
	log_notice(LD_GENERAL, "BEGANCIRC:%lus%luns",
			circ->base_.my_timestamp_began.tv_sec,
			circ->base_.my_timestamp_began.tv_nsec);
	log_notice(LD_GENERAL, "COMPLETEDCIRC:%lus%luns",
			circ->base_.my_timestamp_complete.tv_sec,
			circ->base_.my_timestamp_complete.tv_nsec);

	log_notice(LD_GENERAL, "CPATHSTART:%lus%luns",
			circ->base_.my_timestamp_cpath_start.tv_sec,
			circ->base_.my_timestamp_cpath_start.tv_nsec);
	log_notice(LD_GENERAL, "CPATHEND:%lus%luns",
			circ->base_.my_timestamp_cpath_end.tv_sec,
			circ->base_.my_timestamp_cpath_end.tv_nsec);

	uint64_t my_timecons_ntor = 0;
	uint64_t my_timecons_c25519 = 0;

	for (int i = 0; i < circ->base_.ntor_mes; i = i + 2) {
		my_timecons_ntor += as_nanoseconds(
				&circ->base_.my_timestamps_ntor[i + 1])
						- as_nanoseconds(&circ->base_.my_timestamps_ntor[i]);
	}

	for (int i = 0; i < circ->base_.curve25519_mes; i = i + 2) {
		my_timecons_c25519 += as_nanoseconds(
				&circ->base_.my_timestamps_c25519[i + 1])
						- as_nanoseconds(&circ->base_.my_timestamps_c25519[i]);
	}

	log_notice(LD_GENERAL, "CONSNTOR:%"PRIu64"ns", my_timecons_ntor);
	log_notice(LD_GENERAL, "CONSC25519:%"PRIu64"ns", my_timecons_c25519);

	tor_free(msg);
}

static uint8_t iot_relay_to_device(const uint8_t *target_id, size_t length,
		const uint8_t *payload, uint8_t command) {
	or_connection_t* conn = NULL;

	conn = iot_find_iot_device(target_id);

	if (!conn) {
		return 0;
	}

	// Now send the ticket to IoT device

	var_cell_t *cell;

	cell = var_cell_new(sizeof(iot_ticket_t));

	cell->circ_id = 0;
	cell->command = command;
	cell->cell_num = TLS_CHAN_TO_BASE(conn->chan)->cell_num_out;
	TLS_CHAN_TO_BASE(conn->chan)->cell_num_out++;
	memcpy(cell->payload, payload, length);

	connection_or_write_var_cell_to_buf(cell, conn);

	struct timespec fwd_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &fwd_monotonic);
	log_notice(LD_GENERAL, "FWDTICKET:%lus%luns", fwd_monotonic.tv_sec,
			fwd_monotonic.tv_nsec);

	var_cell_free(cell);

	return 1;
}

void iot_process_relay_pre_ticket(circuit_t *circ, size_t length,
		const uint8_t *payload) {
	(void) circ;

	struct timespec recv_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &recv_monotonic);

	log_info(LD_GENERAL, "Got IoT pre ticket with IoT id of size %ld.",
			length - IOT_ID_LEN);

	iot_relay_to_device(payload, length - IOT_ID_LEN, payload + IOT_ID_LEN,
			CELL_IOT_PRE_TICKET);
}

void iot_process_relay_ticket(circuit_t *circ, size_t length,
		const uint8_t *payload) {
	struct timespec recv_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &recv_monotonic);

	iot_relay_ticket_t *msg = (iot_relay_ticket_t*) payload;

	tor_assert(length == sizeof(iot_relay_ticket_t));

	log_info(LD_GENERAL, "Got IoT ticket with IoT id of size %ld.",
			sizeof(iot_relay_ticket_t));

	if (!splitted_circuits) {
		splitted_circuits = smartlist_new();
	}
	circ->join_cookie = msg->cookie;
	smartlist_add(splitted_circuits, circ);

	log_info(LD_GENERAL, "Added circuit for joining with cookie 0x%08x",
			circ->join_cookie);

	iot_relay_to_device(msg->iot_id, sizeof(iot_ticket_t),
			(uint8_t*) (&msg->ticket), CELL_IOT_TICKET);

	cell_t cell;

	memset(&cell, 0, sizeof(cell_t));
	cell.command = CELL_DESTROY;
	cell.circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;

	append_cell_to_circuit_queue(circ, TO_OR_CIRCUIT(circ)->p_chan, &cell,
			CELL_DIRECTION_IN, 0);

	log_notice(LD_GENERAL, "RECVTICKET:%lus%luns", recv_monotonic.tv_sec,
			recv_monotonic.tv_nsec);
}

void iot_info(or_connection_t *conn, const var_cell_t *cell) {
	log_info(LD_GENERAL,
			"Got a INFO cell for circ_id %u on channel " U64_FORMAT " (%p)",
			(unsigned )cell->circ_id,
			U64_PRINTF_ARG(TLS_CHAN_TO_BASE(conn->chan)->global_identifier),
			TLS_CHAN_TO_BASE(conn->chan));

	//TODO: Here we can resend the buffer on reconnect if counter differ.

	if (connected_iot_dev) {
		or_connection_t *oldconn = NULL;
		log_info(LD_GENERAL, "Looking for already connected IoT device..");
		SMARTLIST_FOREACH_BEGIN(connected_iot_dev, or_connection_t *, c) {
			log_debug(LD_GENERAL, "Check %p", c);
			for (uint8_t i=0; i<IOT_ID_LEN; i++) {
				log_debug(LD_GENERAL, "0x%02x = 0x%02x ?", c->iot_id[i],
						cell->payload[i]);
			}
			if (!memcmp(c->iot_id, cell->payload, IOT_ID_LEN)) {
				log_info(LD_GENERAL, "FOUND! Remove from list to readd it.");
				oldconn = c;
				break;
			}
		}SMARTLIST_FOREACH_END(c);

		if (oldconn) {
			connection_or_close_normally(oldconn, 0); //calls iot_remove_connected_iot()
		}
	} else {
		connected_iot_dev = smartlist_new();
	}

	conn->wide_circ_ids = 1;

	memcpy(conn->iot_id, cell->payload, IOT_ID_LEN);

	smartlist_add(connected_iot_dev, conn);
	log_debug(LD_GENERAL, "Add connection %p to iot smart list.", conn);

	connection_or_set_state_joining(conn);
}

void iot_remove_connected_iot(or_connection_t *conn) {
	if (connected_iot_dev) {
		log_info(LD_GENERAL, "Closed UDP conn. Removing from IoT list..");
		SMARTLIST_FOREACH_BEGIN(connected_iot_dev, or_connection_t *, c) {
			log_debug(LD_GENERAL, "Check %p", c);
			if (conn == c) {
				smartlist_remove(connected_iot_dev, c);
				return;
			}
		}SMARTLIST_FOREACH_END(c);
	}
}

void iot_join(or_connection_t *conn, const var_cell_t *cell) {
	circuit_t *circ = NULL;

	struct timespec req_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &req_monotonic);

	log_info(LD_GENERAL,
			"Got a JOIN cell for circ_id %u on channel " U64_FORMAT " (%p)",
			(unsigned )cell->circ_id,
			U64_PRINTF_ARG(TLS_CHAN_TO_BASE(conn->chan)->global_identifier),
			TLS_CHAN_TO_BASE(conn->chan));

	if (splitted_circuits) {
		// Find circuit by cookie from our smartlist
		SMARTLIST_FOREACH_BEGIN(splitted_circuits, circuit_t *, c) {
			log_info(LD_GENERAL, "Looking for joinable circuit.. Cookie: 0x%08x == 0x%08x ?",
					c->join_cookie, ((uint32_t*)cell->payload)[0]);
			if (((uint32_t*)cell->payload)[0] == c->join_cookie) {
				log_info(LD_GENERAL, "FOUND!");
				circ = c;
				break;
			}
			log_info(LD_GENERAL, "DIDNT MATCH");
		}SMARTLIST_FOREACH_END(c);
	} else {
		log_warn(LD_GENERAL,
				"Got JOIN cell but there never was a circuit ready to join.");
		return;
	}

	if (circ) {
		log_info(LD_GENERAL, "Join circuits by cookie 0x%08x",
				((uint32_t* )cell->payload)[0]);

		// Join circuits
		switch (circ->state) {
		case CIRCUIT_STATE_JOIN_WAIT:
			circuit_set_p_circid_chan(TO_OR_CIRCUIT(circ), cell->circ_id,
					TLS_CHAN_TO_BASE(conn->chan));

			tor_assert(
					TO_OR_CIRCUIT(circ)->p_chan == TLS_CHAN_TO_BASE(conn->chan));


			circ->state = CIRCUIT_STATE_OPEN;

			if (TO_CONN(conn)->state != OR_CONN_STATE_OPEN) {
				connection_or_set_state_open(conn);
			}

			TLS_CHAN_TO_BASE(conn->chan)->cell_num = 1;

			smartlist_remove(splitted_circuits, circ);

			break;
		}


		struct timespec done_monotonic;
		clock_gettime(CLOCK_MONOTONIC, &done_monotonic);
		log_notice(LD_GENERAL, "JOINREQ:%lus%luns", req_monotonic.tv_sec,
				req_monotonic.tv_nsec);
		log_notice(LD_GENERAL, "JOINDONE:%lus%luns", done_monotonic.tv_sec,
				done_monotonic.tv_nsec);

	} else {
		log_info(LD_GENERAL,
				"Tried to join circuit, but cookies didnt match. 0x%08x ?",
				((uint32_t* )cell->payload)[0]);
	}
}
