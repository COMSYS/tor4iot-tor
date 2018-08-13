/*
 * iot_ticket.c
 *
 *  Created on: 07.05.2018
 *      Author: markus
 */

#include "iot_ticket.h"
#include "or.h"

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

#include "nodelist.h"

const uint8_t iot_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
const uint8_t iot_mac_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

const uint8_t iot_iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

const char sp_rsa_id_hex[] = "3A08B33E626B6FB48F2943D2AE3BE7A5B535EB97";
const char iot_id[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

STATIC smartlist_t *splitted_circuits = NULL;
STATIC smartlist_t *connected_iot_dev = NULL;

#define SPLITPOINT_BEFORE_HS(circ) circ->cpath->prev->prev->prev->prev
#define SPLITPOINT(circ) SPLITPOINT_BEFORE_HS(circ)->prev


int iot_set_circ_info(const hs_service_t *hs, iot_circ_info_t *info) {
  (void) hs;

  info->after = 3;
  info->split = node_get_by_hex_id(sp_rsa_id_hex, 0);

  if (!info->split) {
      return -1;
  } else {
    return 1;
  }
}


static void iot_ticket_set_relay_crypto(iot_crypto_aes_relay_t *iot_crypto, crypt_path_t *relay) {
  iot_crypto->b.crypted_bytes = htons(relay->b_crypted_bytes);
  iot_crypto->f.crypted_bytes = htons(relay->f_crypted_bytes);

  memcpy(&iot_crypto->b.aes_key, relay->b_aesctrkey, CIPHER_KEY_LEN);
  memcpy(&iot_crypto->f.aes_key, relay->f_aesctrkey, CIPHER_KEY_LEN);

  log_info(LD_GENERAL, "Forward key starts with %02x, backward key starts with %02x.", relay->f_aesctrkey[0], relay->b_aesctrkey[0]);
}

void iot_inform_split(origin_circuit_t *circ) {
#define DUMMY_SIZE 10

  const char dummy[DUMMY_SIZE];
  relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_SPLIT, dummy,
                                 DUMMY_SIZE, SPLITPOINT_BEFORE_HS(circ));
}

void iot_process_relay_split(circuit_t *circ) {
  circ->already_split = 1; // For logging
  circ->state = CIRCUIT_STATE_JOIN_WAIT;
  log_info(LD_GENERAL, "Circuit %u (id: %" PRIu32 ") marked for split",
             circ->n_circ_id,
             CIRCUIT_IS_ORIGIN(circ) ?
                TO_ORIGIN_CIRCUIT(circ)->global_identifier : 0);
  //channel_flush_cells(TO_OR_CIRCUIT(circ)->p_chan);
}



void iot_ticket_send(origin_circuit_t *circ) {
  iot_split_t *msg;
  crypt_path_t *split_point;
  aes_cnt_cipher_t *encrypt;

  tor_assert(circ);

  struct timespec send_monotonic;
  clock_gettime(CLOCK_MONOTONIC, &send_monotonic);

  log_info(LD_REND, "Sending ticket.");

  //Choose split point such that we have 4 relays left + HS
  split_point = SPLITPOINT(circ);

  msg = tor_malloc(sizeof(iot_split_t));

  // Fill nonce
  crypto_rand((char *)&msg->ticket.nonce, 2);

  // Fill cookies
  crypto_rand((char *)&msg->cookie, 4);
  memcpy(&msg->ticket.cookie, &msg->cookie, 4);
  log_info(LD_GENERAL, "Chosen cookie: 0x%08x  0x%08x", msg->ticket.cookie, msg->cookie);

  //Set key information in ticket
  iot_ticket_set_relay_crypto(&msg->ticket.entry, split_point);
  // Split point is receiver of our ticket. Add payload size.
  msg->ticket.entry.f.crypted_bytes = htons(ntohs(msg->ticket.entry.f.crypted_bytes) + CELL_PAYLOAD_SIZE);

  iot_ticket_set_relay_crypto(&msg->ticket.relay1, split_point->next);
  iot_ticket_set_relay_crypto(&msg->ticket.relay2, split_point->next->next);
  iot_ticket_set_relay_crypto(&msg->ticket.rend, split_point->next->next->next);

  //Set HS material
  memcpy(&msg->ticket.hs_ntor_key, split_point->next->next->next->next->hs_ntor_key, HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

  //Encrypt ticket
  encrypt = aes_new_cipher(iot_key, iot_iv, 128);
  aes_crypt_inplace(encrypt, (char*) &msg->ticket, sizeof(iot_ticket_t)-DIGEST256_LEN);
  aes_cipher_free(encrypt);

  //Set ID of IoT device
  memcpy(msg->iot_id, iot_id, IOT_ID_LEN);

  //Compute MAC
  crypto_hmac_sha256((char*) (msg->ticket.mac), (char*) iot_mac_key, 16, (char*) &(msg->ticket), sizeof(iot_ticket_t)-DIGEST256_LEN);

  //Send it!
  relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_TICKET, (const char*) msg,
                               sizeof(iot_split_t), split_point);

  struct timespec sent_monotonic;
  clock_gettime(CLOCK_MONOTONIC, &sent_monotonic);
  log_notice(LD_GENERAL, "SENDTICKET:%lus%luns", send_monotonic.tv_sec, send_monotonic.tv_nsec);
  log_notice(LD_GENERAL, "SENTTICKET:%lus%luns", sent_monotonic.tv_sec, sent_monotonic.tv_nsec);

  //Close circuit until SP
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);

  tor_free(msg);
}

void iot_process_relay_ticket(circuit_t *circ, uint8_t num, size_t length,
	                      const uint8_t *payload) {
  (void) num;

  struct timespec recv_monotonic;
  clock_gettime(CLOCK_MONOTONIC, &recv_monotonic);

  iot_split_t *msg = (iot_split_t*) payload;

  tor_assert(length == sizeof(iot_split_t));

  log_info(LD_GENERAL, "Got IoT ticket with IoT id of size %ld.", sizeof(iot_split_t));

  or_connection_t* conn = NULL;

  if (connected_iot_dev) {
    SMARTLIST_FOREACH_BEGIN(connected_iot_dev, or_connection_t *, c) {
      log_info(LD_GENERAL, "Looking for connected IoT device.."); // ID: %s == %s ?", c->iot_id, ((uint32_t*)cell->payload)[0]);
      if (!memcmp(c->iot_id, msg->iot_id, IOT_ID_LEN)) {
        log_info(LD_GENERAL, "FOUND!");
        conn = c;
        break;
      }
      log_info(LD_GENERAL, "DIDNT MATCH");
      return;
    } SMARTLIST_FOREACH_END(c);
  } else {
      log_warn(LD_GENERAL, "Got a ticket but there never was a IoT device connected.");
      return;
  }

  if (!splitted_circuits) {
      splitted_circuits = smartlist_new();
  }

  circ->join_cookie = msg->cookie;
  smartlist_add(splitted_circuits, circ);

  log_info(LD_GENERAL, "Added circuit for joining with cookie 0x%08x", circ->join_cookie);


  // Now send the ticket to IoT device

  var_cell_t *cell;

  cell = var_cell_new(sizeof(iot_ticket_t));

  cell->circ_id = 0;
  cell->command = CELL_IOT_TICKET;
  cell->cell_num = TLS_CHAN_TO_BASE(conn->chan)->cell_num_out;
  TLS_CHAN_TO_BASE(conn->chan)->cell_num_out++;
  memcpy(cell->payload, (uint8_t *)&msg->ticket, sizeof(iot_ticket_t));

  connection_or_write_var_cell_to_buf(cell, conn);

  struct timespec fwd_monotonic;
  clock_gettime(CLOCK_MONOTONIC, &fwd_monotonic);

  log_notice(LD_GENERAL, "RECVTICKET:%lus%luns", recv_monotonic.tv_sec, recv_monotonic.tv_nsec);
  log_notice(LD_GENERAL, "FWDTICKET:%lus%luns", fwd_monotonic.tv_sec, fwd_monotonic.tv_nsec);

  var_cell_free(cell);
}

void
iot_info(or_connection_t *conn, const var_cell_t *cell)
{
  log_info(LD_GENERAL,
              "Got a INFO cell for circ_id %u on channel " U64_FORMAT
              " (%p)",
              (unsigned)cell->circ_id,
              U64_PRINTF_ARG(TLS_CHAN_TO_BASE(conn->chan)->global_identifier), TLS_CHAN_TO_BASE(conn->chan));

  //TODO: Here we can resend the buffer on reconnect if counter differ.

  if (connected_iot_dev) {
      or_connection_t *oldconn = NULL;
      SMARTLIST_FOREACH_BEGIN(connected_iot_dev, or_connection_t *, c) {
        log_info(LD_GENERAL, "Looking for already connected IoT device..");
        if (!memcmp(c->iot_id, cell->payload, IOT_ID_LEN)) {
          log_info(LD_GENERAL, "FOUND! Remove from list to readd it.");
          oldconn = c;
          break;
        }
      } SMARTLIST_FOREACH_END(c);

      if (oldconn) {
	  smartlist_remove(connected_iot_dev, oldconn);
      }
    } else {
	connected_iot_dev = smartlist_new();
    }

  conn->wide_circ_ids = 1;

  memcpy(conn->iot_id, cell->payload, IOT_ID_LEN);

  smartlist_add(connected_iot_dev, conn);

  connection_or_set_state_joining(conn);
}

void
iot_join(or_connection_t *conn, const var_cell_t *cell)
{
  circuit_t *circ = NULL;

  struct timespec req_monotonic;
  clock_gettime(CLOCK_MONOTONIC, &req_monotonic);

  log_info(LD_GENERAL,
              "Got a JOIN cell for circ_id %u on channel " U64_FORMAT
              " (%p)",
              (unsigned)cell->circ_id,
              U64_PRINTF_ARG(TLS_CHAN_TO_BASE(conn->chan)->global_identifier), TLS_CHAN_TO_BASE(conn->chan));

  if (splitted_circuits) {
    // Find circuit by cookie from our smartlist
    SMARTLIST_FOREACH_BEGIN(splitted_circuits, circuit_t *, c) {
      log_info(LD_GENERAL, "Looking for joinable circuit.. Cookie: 0x%08x == 0x%08x ?", c->join_cookie, ((uint32_t*)cell->payload)[0]);
      if (((uint32_t*)cell->payload)[0] == c->join_cookie) {
	log_info(LD_GENERAL, "FOUND!");
	circ = c;
	break;
      }
      log_info(LD_GENERAL, "DIDNT MATCH");
    } SMARTLIST_FOREACH_END(c);
  } else {
      log_warn(LD_GENERAL, "Got JOIN cell but there never was a circuit ready to join.");
      return;
  }

  if (circ) {
    log_info(LD_GENERAL, "Join circuits by cookie 0x%08x", ((uint32_t*)cell->payload)[0]);

    tor_assert(circ->state == CIRCUIT_STATE_JOIN_WAIT);

    // Join circuits
    circuit_set_p_circid_chan(TO_OR_CIRCUIT(circ), cell->circ_id, TLS_CHAN_TO_BASE(conn->chan));
    TLS_CHAN_TO_BASE(conn->chan)->cell_num = 1;

    tor_assert(TO_OR_CIRCUIT(circ)->p_chan == TLS_CHAN_TO_BASE(conn->chan));

    circ->state = CIRCUIT_STATE_OPEN;

    smartlist_remove(splitted_circuits, circ);

    if (TO_CONN(conn)->state != OR_CONN_STATE_OPEN) {
	connection_or_set_state_open(conn);
    }

    // Send buffer
    SMARTLIST_FOREACH_BEGIN(circ->iot_buffer, cell_t*, c);
      log_info(LD_GENERAL, "Queue cell with command %d", c->command);
      c->circ_id = TO_OR_CIRCUIT(circ)->p_circ_id; /* switch it */
      append_cell_to_circuit_queue(circ, TO_OR_CIRCUIT(circ)->p_chan, c, CELL_DIRECTION_IN, 0);
      tor_free(c);
    SMARTLIST_FOREACH_END(c);

    struct timespec done_monotonic;
    clock_gettime(CLOCK_MONOTONIC, &done_monotonic);
    log_notice(LD_GENERAL, "JOINREQ:%lus%luns", req_monotonic.tv_sec, req_monotonic.tv_nsec);
    log_notice(LD_GENERAL, "JOINDONE:%lus%luns", done_monotonic.tv_sec, done_monotonic.tv_nsec);

  } else {
    log_info(LD_GENERAL, "Tried to join circuit, but cookies didnt match. 0x%08x ?", ((uint32_t*)cell->payload)[0]);
  }
}
