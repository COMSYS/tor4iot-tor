/*
 * iot_delegation.c
 *
 *  Created on: 23.01.2019
 *      Author: markus
 */

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
#include "circpathbias.h"

#include "hs_circuit.h"

#include "connection_edge.h"
#include "iot_delegation.h"
#include "iot.h"

const char iot_id[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

const uint8_t iot_key[] =
{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
const uint8_t iot_mac_key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
		14, 15 };

#define SPLITPOINT_BEFORE_HS(circ) circ->cpath->prev->prev->prev->prev
#define SPLITPOINT(circ) SPLITPOINT_BEFORE_HS(circ)->prev

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

void iot_ticket_send(origin_circuit_t *circ, uint8_t type) {
	iot_relay_ticket_t *msg;
	crypt_path_t *split_point;
	aes_cnt_cipher_t *encrypt;

	tor_assert(circ);

	clock_gettime(CLOCK_MONOTONIC, &circ->iot_mes_handoverticketstart);

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

	clock_gettime(CLOCK_MONOTONIC, &circ->iot_mes_handoverticketend);

	//Send it!
	relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_TICKET,
			(const char* ) msg, sizeof(iot_relay_ticket_t), split_point);

	tor_free(msg);
}

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

	circ->base_.iot_entry_conn = conn;
	circ->base_.handover = handover;

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

	clock_gettime(CLOCK_MONOTONIC, &circ->iot_mes_ticketstart);

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
	crypto_hmac_sha256((char *) circ->base_.iot_expect_hmac, (char *) iot_mac_key, 16, (char*) msg->ticket.hs_ntor_key,
				HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

	log_debug(LD_GENERAL, "Expecting HMAC starts with %02x %02x", circ->base_.iot_expect_hmac[0], circ->base_.iot_expect_hmac[1]);

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
			RELAY_COMMAND_FAST_TICKET,
			(const char*) msg,
			sizeof(iot_relay_fast_ticket_t),
			circ->cpath->prev)<0) {
		/* circ is already marked for close */
		log_warn(LD_GENERAL, "Couldn't send FAST_TICKET cell");
	}

	clock_gettime(CLOCK_MONOTONIC, &circ->iot_mes_ticketend);

	pathbias_count_use_attempt(circ);
	finalize_rend_circuit(circ, cpath, is_service_side);
	link_apconn_to_circ(circ->base_.iot_entry_conn, circ, cpath);
}

int
iot_client_entry_circuit_has_opened(origin_circuit_t *circ) {
	iot_fast_ticket_send(circ);

	// Lets wait for the FAST_TICKET_RELAYED2 message
	TO_CONN(ENTRY_TO_EDGE_CONN(circ->base_.iot_entry_conn))->state = AP_CONN_STATE_IOT_WAIT;

	return 0;
}

static void
print_mes(const char *label, struct timespec *time) {
	if (time->tv_sec != 0 || time->tv_nsec != 0) {
	  log_notice(LD_GENERAL, "%s:%lus%luns", label, time->tv_sec, time->tv_nsec);
	}
}

void
iot_delegation_print_measurements(circuit_t *circ) {
	origin_circuit_t *o_circ = TO_ORIGIN_CIRCUIT(circ);
	crypt_path_t *cpath_iot, *cpath_temp;

	if (circ->iot_entry_conn) {
		print_mes("START", &circ->iot_entry_conn->iot_mes_start);
	}

	print_mes("IP_CPATHSTART", &o_circ->iot_mes_ipcpathstart);
	print_mes("IP_CPATHEND", &o_circ->iot_mes_ipcpathend);
	print_mes("IP_CIRCSTART", &o_circ->iot_mes_ipcircstart);
	print_mes("IP_CIRCEND", &o_circ->iot_mes_ipcircend);

	print_mes("INTRODUCE2_FROM_BUF", &o_circ->iot_mes_hs_introduce2_from_buf);
	print_mes("INTRODUCE2_RECEIVED", &o_circ->iot_mes_hs_introduce2_received);
	print_mes("CPATHSTART", &o_circ->iot_mes_cpathstart);
	print_mes("CPATHEND", &o_circ->iot_mes_cpathend);
	print_mes("CIRCSTART", &o_circ->iot_mes_circstart);

	cpath_iot = o_circ->cpath->prev;
	cpath_temp = o_circ->cpath;

	while (cpath_temp != cpath_iot) {
		print_mes("NTOR1START", &cpath_temp->iot_mes_ntor1start);
		print_mes("X255191START", &cpath_temp->iot_mes_x255191start);
		print_mes("X255191END", &cpath_temp->iot_mes_x255191end);
		print_mes("NTOR1END", &cpath_temp->iot_mes_ntor1end);

		print_mes("NTOR2START", &cpath_temp->iot_mes_ntor2start);
		print_mes("X255192START", &cpath_temp->iot_mes_x255192start);
		print_mes("X255192END", &cpath_temp->iot_mes_x255192end);
		print_mes("X255193START", &cpath_temp->iot_mes_x255193start);
		print_mes("X255193END", &cpath_temp->iot_mes_x255193end);
		print_mes("NTOR2END", &cpath_temp->iot_mes_ntor2end);

		cpath_temp = cpath_temp->next;
	}

	print_mes("CIRCEND", &o_circ->iot_mes_circend);

	print_mes("INTRODUCE1_READY", &o_circ->iot_mes_hs_introduce1_ready);
	print_mes("INTRODUCE1_TO_BUF", &o_circ->iot_mes_hs_introduce1_to_buf);

	print_mes("RENDEZVOUS2_FROM_BUF", &o_circ->iot_mes_hs_rend2_from_buf);
	print_mes("RENDEZVOUS2", &o_circ->iot_mes_hs_rend2_received);

	print_mes("TICKETSTART", &o_circ->iot_mes_ticketstart);
	print_mes("TICKETEND", &o_circ->iot_mes_ticketend);
	print_mes("TICKET_TO_BUF", &o_circ->iot_mes_ticket_to_buf);

	print_mes("TICKETACK_FROM_BUF", &o_circ->iot_mes_ticketack_from_buf);
	print_mes("TICKETACK", &o_circ->iot_mes_ticketack);

	print_mes("HANDOVERTICKETSTART", &o_circ->iot_mes_handoverticketstart);
	print_mes("HANDOVERTICKETEND", &o_circ->iot_mes_handoverticketend);
	print_mes("HANDOVERTICKET_TO_BUF", &o_circ->iot_mes_handoverticket_to_buf);

	print_mes("BEGIN_READY", &o_circ->iot_mes_hs_begin_ready);
	print_mes("BEGIN_TO_BUF", &o_circ->iot_mes_hs_begin_to_buf);

	print_mes("CONNECTED_RECV", &o_circ->iot_mes_hs_connected);
	print_mes("CONNECTED_FROM_BUF", &o_circ->iot_mes_hs_connected_from_buf);

	log_notice(LD_GENERAL, "CHOSENRELAYS:%s", circuit_list_path(o_circ, 0));
}
