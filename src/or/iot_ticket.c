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
#include "torlog.h"

const uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
const uint8_t mac_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

const uint8_t iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void iot_ticket_send(origin_circuit_t *circ) {
  iot_split_t *msg;
  crypt_path_t *split_point;
  aes_cnt_cipher_t *encrypt;

  tor_assert(circ);

  log_notice(LD_REND, "Sending ticket.");

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
  msg->iot_address.in_addr[0] = 0x00000000;
  msg->iot_address.in_addr[1] = 0x00000000;
  msg->iot_address.in_addr[2] = 0x00000000;
  msg->iot_address.in_addr[3] = 0x00000001;

  inet_pton(AF_INET6, "::1", &(msg->iot_address.in_addr));
  msg->iot_address.port = htons(10000);

  //Send it!
  relay_send_command_from_edge(0, TO_CIRCUIT(circ), RELAY_COMMAND_SPLIT, (const char*) msg,
                               sizeof(iot_split_t), split_point);

  //Close circuit until SP
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);

  tor_free(msg);
}


void iot_process_relay_split(circuit_t *circ, size_t length,
	                     const uint8_t *payload) {
  iot_split_t *msg = (iot_split_t*) payload;
  iot_join_req_t join_req;

  char ipstr[INET6_ADDRSTRLEN];

  tor_assert(length == sizeof(iot_split_t));

  log_info(LD_GENERAL, "Got IoT ticket. Send it to device now.");

#define IOT_JOIN_ID 12

  // Split circuit
  circ->already_split = 1;
  circ->join_id = IOT_JOIN_ID;

  // Construct join req for IoT device
  join_req.join_id = IOT_JOIN_ID;
  memcpy(&join_req.ticket, &msg->ticket, sizeof(iot_ticket_t));

  struct sockaddr_in6 si_other;
  int s, slen=sizeof(si_other);

  s=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  tor_assert(s!=-1);

  memset((char *) &si_other, 0, sizeof(si_other));

  si_other.sin6_family = AF_INET6;
  si_other.sin6_port = msg->iot_address.port;
  memcpy(&si_other.sin6_addr, &msg->iot_address.in_addr, 16);

  inet_ntop(AF_INET6, &(si_other.sin6_addr), ipstr, INET6_ADDRSTRLEN);

  log_info(LD_GENERAL, "Sending it to %s at port %d", ipstr, ntohs(si_other.sin6_port));

  sendto(s, &join_req, sizeof(iot_join_req_t), 0, (struct sockaddr *) &si_other, slen);

  close(s);
}
