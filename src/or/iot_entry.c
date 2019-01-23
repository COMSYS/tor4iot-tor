/*
 * iot_entry.c
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

#include "hs_circuit.h"

#include "connection_edge.h"
#include "iot_entry.h"
#include "iot.h"

uint32_t iot_circ_id = 17;

STATIC smartlist_t *splitted_circuits = NULL;
STATIC smartlist_t *connected_iot_dev = NULL;

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
