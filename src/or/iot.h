#ifndef SRC_OR_IOT_H_
#define SRC_OR_IOT_H_

#include "or.h"

typedef struct hs_service_t hs_service_t;

#pragma pack(push, 1)
/**
 * Struct for encryption and decryption information, i.e., AES key and already
 * crypted bytes.
 */
typedef struct iot_crypto_aes_t {
  uint8_t aes_key[16];
  uint16_t crypted_bytes;
} iot_crypto_aes_t;

/**
 * Structure combining sending and receiving direction crypto for a relay. Used
 * inside the ticket representation.
 */
typedef struct iot_crypto_aes_relay_t {
  iot_crypto_aes_t f;
  iot_crypto_aes_t b;
} iot_crypto_aes_relay_t;

#define IOT_TICKET_NONCE_LEN 16

/**
 * Representation of the ticket sent by the DHS
 */
typedef struct iot_ticket_t {
  uint8_t nonce[IOT_TICKET_NONCE_LEN];

  uint32_t cookie;

  uint8_t type;
#define IOT_TICKET_TYPE_HS 1
#define IOT_TICKET_TYPE_CLIENT 2

  iot_crypto_aes_relay_t entry;
  iot_crypto_aes_relay_t relay1;
  iot_crypto_aes_relay_t relay2;
  iot_crypto_aes_relay_t rend;

  uint8_t f_rend_init_digest[DIGEST_LEN];

  uint8_t hs_ntor_key[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];

  uint8_t rend_info[HSv3_REND_INFO];

  uint8_t mac[DIGEST256_LEN];
} iot_ticket_t;

/**
 * Representation of the relay ticket cell payload sent by the DHS to the IoT Entry.
 */
typedef struct iot_relay_ticket_t {
  uint8_t iot_id[IOT_ID_LEN];

  uint32_t cookie;

  iot_ticket_t ticket;
} iot_relay_ticket_t;

/**
 * Representation of the fast ticket cell a client sends to the IoT device wo DHS
 */
typedef struct iot_fast_ticket_t {
  uint8_t nonce[IOT_TICKET_NONCE_LEN];

  uint32_t cookie;

  uint8_t hs_ntor_key[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];

  uint8_t mac[DIGEST256_LEN];
} iot_fast_ticket_t;

typedef struct iot_relay_fast_ticket_t {
  uint8_t iot_id[IOT_ID_LEN];

  uint32_t cookie;

  iot_fast_ticket_t ticket;
} iot_relay_fast_ticket_t;

#pragma pack(pop)

#endif /* SRC_OR_IOT_H_ */
