/*
 * iot_ticket.h
 *
 *  Created on: 07.05.2018
 *      Author: markus
 */

#ifndef SRC_OR_IOT_TICKET_H_
#define SRC_OR_IOT_TICKET_H_

#include "or.h"

typedef struct iot_crypto_t {
  uint8_t aes_key[16];
  uint8_t aes_iv[16];

  uint32_t sha_state[5];
  uint32_t sha_count[2];
  uint8_t sha_buffer[16];
} iot_crypto_t;

typedef struct iot_ticket_t {
  uint16_t nonce;

  iot_crypto_t sp_f;
  iot_crypto_t sp_b;

  iot_crypto_t middle_f;
  iot_crypto_t middle_b;

  iot_crypto_t exit_f;
  iot_crypto_t exit_b;

  uint8_t mac[16];
} iot_ticket_t;

typedef struct iot_split_t {
  struct {
    uint32_t in_addr[4];
    uint16_t port;
  } iot_address;

  iot_ticket_t ticket;
} iot_split_t;

void iot_ticket_send(origin_circuit_t *circ);

void iot_process_relay_split(circuit_t *circ, const crypt_path_t *layer_hint,
	                     int command, size_t length,
	                     const uint8_t *payload);

#endif /* SRC_OR_IOT_TICKET_H_ */
