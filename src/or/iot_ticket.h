/*
 * iot_ticket.h
 *
 *  Created on: 07.05.2018
 *      Author: markus
 */

#ifndef SRC_OR_IOT_TICKET_H_
#define SRC_OR_IOT_TICKET_H_

#include "or.h"

#pragma pack(push, 1)
typedef struct iot_crypto_aes_t {
  uint8_t aes_key[16];
  uint8_t aes_iv[16];

  //TODO: num needed?
} iot_crypto_aes_t;

typedef struct iot_crypto_aes_relay_t {
  iot_crypto_aes_t f;
  iot_crypto_aes_t b;
} iot_crypto_aes_relay_t;

typedef struct iot_ticket_t {
  uint16_t nonce;

  struct {
    uint32_t in_addr[4];
    uint16_t port;
  } sp_address;

  uint32_t cookie;

  iot_crypto_aes_relay_t sp;
  iot_crypto_aes_relay_t middle;
  iot_crypto_aes_relay_t rend;

  uint8_t hs_ntor_key[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];

  uint8_t mac[DIGEST256_LEN];
} iot_ticket_t;

typedef struct iot_split_t {
  struct {
    uint32_t in_addr[4];
    uint16_t port;
  } iot_address;

  uint32_t cookie;

  iot_ticket_t ticket;
} iot_split_t;

#pragma pack(pop)

void iot_ticket_send(origin_circuit_t *circ);

void iot_process_relay_split(circuit_t *circ, size_t length,
	                     const uint8_t *payload);

void iot_join(or_connection_t *conn, const var_cell_t *cell);

#endif /* SRC_OR_IOT_TICKET_H_ */
