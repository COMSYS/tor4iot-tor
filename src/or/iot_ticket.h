/*
 * iot_ticket.h
 *
 *  Created on: 07.05.2018
 *      Author: markus
 */

#ifndef SRC_OR_IOT_TICKET_H_
#define SRC_OR_IOT_TICKET_H_

#include "or.h"

typedef struct hs_service_t hs_service_t;

#pragma pack(push, 1)
typedef struct iot_crypto_aes_t {
  uint8_t aes_key[16];
  uint16_t crypted_bytes;

  //TODO: num needed?
} iot_crypto_aes_t;

typedef struct iot_crypto_aes_relay_t {
  iot_crypto_aes_t f;
  iot_crypto_aes_t b;
} iot_crypto_aes_relay_t;

#define IOT_TICKET_NONCE_LEN 16

typedef struct iot_ticket_t {
  uint8_t nonce[IOT_TICKET_NONCE_LEN];

  uint32_t cookie;

  iot_crypto_aes_relay_t entry;
  iot_crypto_aes_relay_t relay1;
  iot_crypto_aes_relay_t relay2;
  iot_crypto_aes_relay_t rend;

  uint8_t hs_ntor_key[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];

  uint8_t mac[DIGEST256_LEN];
} iot_ticket_t;

typedef struct iot_relay_ticket_t {
  uint8_t iot_id[IOT_ID_LEN];

  uint32_t cookie;

  iot_ticket_t ticket;
} iot_relay_ticket_t;

#pragma pack(pop)

int iot_set_circ_info(const hs_service_t *hs, iot_circ_info_t *info);

void iot_ticket_send(origin_circuit_t *circ);

void iot_inform_split(origin_circuit_t *circ);

void iot_process_relay_split(circuit_t *circ);

void iot_process_relay_pre_ticket(circuit_t *circ, size_t length,
	                     const uint8_t *payload);

void iot_process_relay_ticket(circuit_t *circ, size_t length,
	                     const uint8_t *payload);

void iot_info(or_connection_t *conn, const var_cell_t *cell);

void iot_remove_connected_iot (or_connection_t *conn);

void iot_join(or_connection_t *conn, const var_cell_t *cell);

#endif /* SRC_OR_IOT_TICKET_H_ */
