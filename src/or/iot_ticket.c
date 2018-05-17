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

const uint8_t iot_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
const uint8_t iot_mac_key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

const uint8_t iot_iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static void iot_ticket_set_relay_crypto(iot_crypto_aes_relay_t *iot_crypto, crypt_path_t *relay) {
  aes_get_iv(relay->b_crypto, iot_crypto->b.aes_iv);
  aes_get_iv(relay->f_crypto, iot_crypto->f.aes_iv);

  memcpy(&iot_crypto->b.aes_key, relay->b_aesctrkey, CIPHER_KEY_LEN);
  memcpy(&iot_crypto->f.aes_key, relay->f_aesctrkey, CIPHER_KEY_LEN);
}

void iot_ticket_send(origin_circuit_t *circ) {
  iot_split_t *msg;
  crypt_path_t *split_point;
  aes_cnt_cipher_t *encrypt;

  tor_assert(circ);

  log_notice(LD_REND, "Sending ticket.");

  //Choose split point such that we have 3 relays left
  split_point = circ->cpath->prev->prev->prev;

  msg = tor_malloc(sizeof(iot_split_t));

  // Set SP address in ticket
  // XXX: THIS IS NOT THE UDP PORT, WILL FAIL IF IT IS DIFFERENT FROM TCP PORT
  //tor_assert(split_point->extend_info->addr.family == AF_INET6);
  memcpy(&msg->ticket.sp_address.in_addr, &split_point->extend_info->addr.addr.in6_addr, 4*32);
  msg->ticket.sp_address.port = split_point->extend_info->port;

  //Set key information in ticket
  iot_ticket_set_relay_crypto(&msg->ticket.sp, split_point);
  iot_ticket_set_relay_crypto(&msg->ticket.middle, split_point->next);
  iot_ticket_set_relay_crypto(&msg->ticket.rend, split_point->next->next);

  //Set HS material
  memcpy(&msg->ticket.hs_ntor_key, split_point->next->next->next->hs_ntor_key, HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

  //Encrypt ticket
  encrypt = aes_new_cipher(iot_key, iot_iv, 128);
  aes_crypt_inplace(encrypt, (char*) &msg->ticket, sizeof(iot_ticket_t)-DIGEST256_LEN);
  aes_cipher_free(encrypt);

  //Compute MAC
  crypto_hmac_sha256((char*) msg->ticket.mac, (char*) iot_mac_key, 16, (char*) &(msg->ticket), sizeof(iot_ticket_t)-DIGEST256_LEN);

  //Set address and port information of IoT device
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

  char ipstr[INET6_ADDRSTRLEN];

  tor_assert(length == sizeof(iot_split_t));

  log_info(LD_GENERAL, "Got IoT ticket with IoT address information of size %ld.", sizeof(iot_split_t));

#define IOT_JOIN_ID 12

  // TODO: Save cookie
  circ->already_split = 1;
  circ->join_id = IOT_JOIN_ID;

  struct sockaddr_in6 si_other;
  int s, slen=sizeof(si_other);

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
