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

const uint8_t iot_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
const uint8_t iot_mac_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

const uint8_t iot_iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

STATIC smartlist_t *splitted_circuits = NULL;

#define SPLITPOINT(circ) circ->cpath->prev->prev->prev->prev


static void iot_ticket_set_relay_crypto(iot_crypto_aes_relay_t *iot_crypto, crypt_path_t *relay) {
  aes_get_iv(relay->b_crypto, iot_crypto->b.aes_iv);
  aes_get_iv(relay->f_crypto, iot_crypto->f.aes_iv);

  memcpy(&iot_crypto->b.aes_key, relay->b_aesctrkey, CIPHER_KEY_LEN);
  memcpy(&iot_crypto->f.aes_key, relay->f_aesctrkey, CIPHER_KEY_LEN);
}

void iot_inform_split(origin_circuit_t *circ) {
  relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_SPLIT, NULL,
                                 0, SPLITPOINT(circ));
}

void iot_process_relay_split(circuit_t *circ) {
  circ->already_split = 1; // Start buffering data
  //channel_flush_cells(TO_OR_CIRCUIT(circ)->p_chan);
}

void iot_ticket_send(origin_circuit_t *circ) {
  iot_split_t *msg;
  crypt_path_t *split_point;
  aes_cnt_cipher_t *encrypt;

  tor_assert(circ);

  log_notice(LD_REND, "Sending ticket.");

  //Choose split point such that we have 3 relays left + HS
  split_point = SPLITPOINT(circ);

  msg = tor_malloc(sizeof(iot_split_t));

  // Fill nonce
  crypto_rand((char *)&msg->ticket.nonce, 2);

  // Fill cookies
  crypto_rand((char *)&msg->cookie, 4);
  memcpy(&msg->ticket.cookie, &msg->cookie, 4);
  log_info(LD_GENERAL, "Chosen cookie: 0x%08x  0x%08x", msg->ticket.cookie, msg->cookie);

  // Set SP address in ticket
  // XXX: THIS IS NOT THE UDP PORT, WILL FAIL IF IT IS DIFFERENT FROM TCP PORT
  //tor_assert(split_point->extend_info->addr.family == AF_INET6);
  memcpy(&msg->ticket.sp_address.in_addr, &split_point->extend_info->sp.addr.addr.in6_addr, 4*4);
  msg->ticket.sp_address.port = htons(split_point->extend_info->sp.port);

  //Set key information in ticket
  iot_ticket_set_relay_crypto(&msg->ticket.sp, split_point);
  iot_ticket_set_relay_crypto(&msg->ticket.middle, split_point->next);
  iot_ticket_set_relay_crypto(&msg->ticket.rend, split_point->next->next);

  //Set HS material
  memcpy(&msg->ticket.hs_ntor_key, split_point->next->next->next->hs_ntor_key, HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

  log_info(LD_GENERAL, "IoT device has to connect to SP on port %d", ntohs(msg->ticket.sp_address.port));

  //Encrypt ticket
  encrypt = aes_new_cipher(iot_key, iot_iv, 128);
  aes_crypt_inplace(encrypt, (char*) &msg->ticket, sizeof(iot_ticket_t)-DIGEST256_LEN);
  aes_cipher_free(encrypt);

  //Set address and port information of IoT device
  inet_pton(AF_INET6, "::1", &(msg->iot_address.in_addr));
  msg->iot_address.port = htons(10000);

  //Compute MAC
  crypto_hmac_sha256((char*) (msg->ticket.mac), (char*) iot_mac_key, 16, (char*) &(msg->ticket), sizeof(iot_ticket_t)-DIGEST256_LEN);

  //Send it!
  relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_TICKET1, (const char*) msg,
                               sizeof(iot_split_t), split_point);

  //Close circuit until SP
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);

  tor_free(msg);
}

void iot_process_relay_ticket(circuit_t *circ, uint8_t num, size_t length,
	                      const uint8_t *payload) {
  iot_split_t *msg = (iot_split_t*) payload;

  char ipstr[INET6_ADDRSTRLEN];

  tor_assert(length == sizeof(iot_split_t));

  log_info(LD_GENERAL, "Got IoT ticket with IoT address information of size %ld.", sizeof(iot_split_t));

  struct sockaddr_in6 si_other;
  int s, slen=sizeof(si_other);


  if (!splitted_circuits) {
      splitted_circuits = smartlist_new();
  }

  circ->join_cookie = msg->cookie;
  smartlist_add(splitted_circuits, circ);

  log_info(LD_GENERAL, "Added circuit for joining with cookie 0x%08x", circ->join_cookie);


  // Now send the ticket to IoT device

  s=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  tor_assert(s!=-1);

  memset((char *) &si_other, 0, sizeof(si_other));

  si_other.sin6_family = AF_INET6;
  si_other.sin6_port = msg->iot_address.port;
  memcpy(&si_other.sin6_addr, &msg->iot_address.in_addr, 16);

  inet_ntop(AF_INET6, &(si_other.sin6_addr), ipstr, INET6_ADDRSTRLEN);

  log_info(LD_GENERAL, "Sending ticket of size %ld to %s at port %d", sizeof(iot_ticket_t), ipstr, ntohs(si_other.sin6_port));

  sendto(s, &msg->ticket, sizeof(iot_ticket_t), 0, (struct sockaddr *) &si_other, slen);

  close(s);
}

void
iot_join(or_connection_t *conn, const var_cell_t *cell)
{
  circuit_t *circ = NULL;


  log_info(LD_GENERAL,
	    "Received a variable-length cell with command %d in orconn "
            "state %s [%d].",
            (int)(cell->command),
            conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
            (int)(TO_CONN(conn)->state));

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

  if (circ) {
    log_info(LD_GENERAL, "Join circuits by cookie 0x%08x", ((uint32_t*)cell->payload)[0]);

    // Join circuits
    circuit_set_p_circid_chan(TO_OR_CIRCUIT(circ), (circid_t) cell->circ_id, TLS_CHAN_TO_BASE(conn->chan));
    circ->already_split = 0;

    smartlist_remove(splitted_circuits, circ);

    connection_or_set_state_open(conn);

    // Send buffer
    SMARTLIST_FOREACH_BEGIN(circ->iot_buffer, cell_t*, c);
      log_info(LD_GENERAL, "Queue cell with command %d", c->command);
      c->circ_id = TO_OR_CIRCUIT(circ)->p_circ_id; /* switch it */
      append_cell_to_circuit_queue(circ, TO_OR_CIRCUIT(circ)->p_chan, c, CELL_DIRECTION_IN, 0);
      // XXX: FREE cells?
      tor_free(c);
    SMARTLIST_FOREACH_END(c);
  } else {
      log_info(LD_GENERAL, "Tried to join circuit, but cookies didnt match. 0x%08x ?", ((uint32_t*)cell->payload)[0]);
  }
}
