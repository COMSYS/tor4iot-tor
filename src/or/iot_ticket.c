/*
 * iot_ticket.c
 *
 *  Created on: 07.05.2018
 *      Author: markus
 */

#include "iot_ticket.h"
#include "or.h"

#include "crypto.h"
#include "main.h"
#include "aes.h"
#include "relay.h"
#include "circuitlist.h"

const uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
const uint8_t mac_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

const uint8_t iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void iot_ticket_send(origin_circuit_t *circ) {
  iot_split_t *msg;
  crypt_path_t *split_point;
  aes_cnt_cipher_t *encrypt;

  tor_assert(circ);

  //Choose split point such that we have 3 relays left
  split_point = circ->cpath->prev->prev->prev;

  msg = tor_malloc(sizeof(iot_split_t));

  //TODO: Set key information in ticket
  //memcpy(msg->ticket.sp_b.sha_state, split_point->b_digest->d.sha1, 20);
  //memcpy(msg->ticket.sp_b.sha_count, split_point->b_digest->d.sha1 + 20, 2);
  //memcpy(msg->ticket.sp_b.sha_buffer)

  //Encrypt ticket
  encrypt = aes_new_cipher(key, iv, 128);
  aes_crypt_inplace(encrypt, (char*) &msg->ticket, sizeof(iot_ticket_t)-16);
  aes_cipher_free(encrypt);

  //Compute MAC
  crypto_hmac_sha256((char*) msg->ticket.mac, (char*) mac_key, 16, (char*) &msg->ticket, sizeof(iot_ticket_t)-16);

  //Set address information of IoT device
  msg->iot_address.in_addr[0] = 0xabcdabcd;
  msg->iot_address.in_addr[1] = 0xabcdabcd;
  msg->iot_address.in_addr[2] = 0xabcdabcd;
  msg->iot_address.in_addr[3] = 0xabcdabcd;

  msg->iot_address.port = htonl(1234);

  //Send it!
  relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_SPLIT, (const char*) msg,
                               sizeof(iot_split_t), split_point);

  //Close circuit until SP
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);

  tor_free(msg);
}

//circ, layer_hint, rh.command, rh.length, cell->payload+RELAY_HEADER_SIZE
void iot_process_relay_split(circuit_t *circ, const crypt_path_t *layer_hint,
	                     int command, size_t length,
	                     const uint8_t *payload) {
  iot_split_t *msg = (iot_split_t*) payload;

  //TODO: Send ticket to IoT device

  return;
}
