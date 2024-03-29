/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.h
 * \brief Header file containing service data for the HS subsytem.
 **/

#ifndef TOR_HS_SERVICE_H
#define TOR_HS_SERVICE_H

#include "crypto_curve25519.h"
#include "crypto_ed25519.h"
#include "replaycache.h"

#include "hs_common.h"
#include "hs_descriptor.h"
#include "hs_ident.h"
#include "hs_intropoint.h"

/* Trunnel */
#include "hs/cell_establish_intro.h"

/* When loading and configuring a service, this is the default version it will
 * be configured for as it is possible that no HiddenServiceVersion is
 * present. */
#define HS_SERVICE_DEFAULT_VERSION HS_VERSION_TWO

/* As described in the specification, service publishes their next descriptor
 * at a random time between those two values (in seconds). */
#define HS_SERVICE_NEXT_UPLOAD_TIME_MIN (60 * 60)
#define HS_SERVICE_NEXT_UPLOAD_TIME_MAX (120 * 60)

/* Service side introduction point. */
typedef struct hs_service_intro_point_t {
  /* Top level intropoint "shared" data between client/service. */
  hs_intropoint_t base;

  /* Onion key of the introduction point used to extend to it for the ntor
   * handshake. */
  curve25519_public_key_t onion_key;

  /* Authentication keypair used to create the authentication certificate
   * which is published in the descriptor. */
  ed25519_keypair_t auth_key_kp;

  /* Encryption keypair for the "ntor" type. */
  curve25519_keypair_t enc_key_kp;

  /* Legacy key if that intro point doesn't support v3. This should be used if
   * the base object legacy flag is set. */
  crypto_pk_t *legacy_key;

  /* Amount of INTRODUCE2 cell accepted from this intro point. */
  uint64_t introduce2_count;

  /* Maximum number of INTRODUCE2 cell this intro point should accept. */
  uint64_t introduce2_max;

  /* The time at which this intro point should expire and stop being used. */
  time_t time_to_expire;

  /* The amount of circuit creation we've made to this intro point. This is
   * incremented every time we do a circuit relaunch on this intro point which
   * is triggered when the circuit dies but the node is still in the
   * consensus. After MAX_INTRO_POINT_CIRCUIT_RETRIES, we give up on it. */
  uint32_t circuit_retries;

  /* Set if this intro point has an established circuit. */
  unsigned int circuit_established : 1;

  /* Replay cache recording the encrypted part of an INTRODUCE2 cell that the
   * circuit associated with this intro point has received. This is used to
   * prevent replay attacks. */
  replaycache_t *replay_cache;
} hs_service_intro_point_t;

/* Object handling introduction points of a service. */
typedef struct hs_service_intropoints_t {
  /* The time at which we've started our retry period to build circuits. We
   * don't want to stress circuit creation so we can only retry for a certain
   * time and then after we stop and wait. */
  time_t retry_period_started;

  /* Number of circuit we've launched during a single retry period. */
  unsigned int num_circuits_launched;

  /* Contains the current hs_service_intro_point_t objects indexed by
   * authentication public key. */
  digest256map_t *map;

  /* Contains node's identity key digest that were introduction point for this
   * descriptor but were retried to many times. We keep those so we avoid
   * re-picking them over and over for a circuit retry period.
   * XXX: Once we have #22173, change this to only use ed25519 identity. */
  digestmap_t *failed_id;
} hs_service_intropoints_t;

/* Representation of a service descriptor. */
typedef struct hs_service_descriptor_t {
  /* Decoded descriptor. This object is used for encoding when the service
   * publishes the descriptor. */
  hs_descriptor_t *desc;

  /* Descriptor signing keypair. */
  ed25519_keypair_t signing_kp;

  /* Blinded keypair derived from the master identity public key. */
  ed25519_keypair_t blinded_kp;

  /* When is the next time when we should upload the descriptor. */
  time_t next_upload_time;

  /* Introduction points assign to this descriptor which contains
   * hs_service_intropoints_t object indexed by authentication key (the RSA
   * key if the node is legacy). */
  hs_service_intropoints_t intro_points;

  /* The time period number this descriptor has been created for. */
  uint64_t time_period_num;

  /* True iff we have missing intro points for this descriptor because we
   * couldn't pick any nodes. */
  unsigned int missing_intro_points : 1;

  /** List of the responsible HSDirs (their b64ed identity digest) last time we
   *  uploaded this descriptor. If the set of responsible HSDirs is different
   *  from this list, this means we received new dirinfo and we need to
   *  reupload our descriptor. */
  smartlist_t *previous_hsdirs;
} hs_service_descriptor_t;

/* Service key material. */
typedef struct hs_service_keys_t {
  /* Master identify public key. */
  ed25519_public_key_t identity_pk;
  /* Master identity private key. */
  ed25519_secret_key_t identity_sk;
  /* True iff the key is kept offline which means the identity_sk MUST not be
   * used in that case. */
  unsigned int is_identify_key_offline : 1;
} hs_service_keys_t;

/* Service configuration. The following are set from the torrc options either
 * set by the configuration file or by the control port. Nothing else should
 * change those values. */
typedef struct hs_service_config_t {
  /* Protocol version of the service. Specified by HiddenServiceVersion
   * option. */
  uint32_t version;

  /* List of rend_service_port_config_t */
  smartlist_t *ports;

  /* Path on the filesystem where the service persistent data is stored. NULL
   * if the service is ephemeral. Specified by HiddenServiceDir option. */
  char *directory_path;

  /* The maximum number of simultaneous streams per rendezvous circuit that
   * are allowed to be created. No limit if 0. Specified by
   * HiddenServiceMaxStreams option. */
  uint64_t max_streams_per_rdv_circuit;

  /* If true, we close circuits that exceed the max_streams_per_rdv_circuit
   * limit. Specified by HiddenServiceMaxStreamsCloseCircuit option. */
  unsigned int max_streams_close_circuit : 1;

  /* How many introduction points this service has. Specified by
   * HiddenServiceNumIntroductionPoints option. */
  unsigned int num_intro_points;

  /* True iff we allow request made on unknown ports. Specified by
   * HiddenServiceAllowUnknownPorts option. */
  unsigned int allow_unknown_ports : 1;

  /* If true, this service is a Single Onion Service. Specified by
   * HiddenServiceSingleHopMode and HiddenServiceNonAnonymousMode options. */
  unsigned int is_single_onion : 1;

  /* If true, allow group read permissions on the directory_path. Specified by
   * HiddenServiceDirGroupReadable option. */
  unsigned int dir_group_readable : 1;

  /* Is this service ephemeral? */
  unsigned int is_ephemeral : 1;

  // Tor4IoT: Marker for IoT HS
  unsigned int is_delegation : 1;
} hs_service_config_t;

/* Service state. */
typedef struct hs_service_state_t {
  /* The time at which we've started our retry period to build circuits. We
   * don't want to stress circuit creation so we can only retry for a certain
   * time and then after we stop and wait. */
  time_t intro_circ_retry_started_time;

  /* Number of circuit we've launched during a single retry period. This
   * should never go over MAX_INTRO_CIRCS_PER_PERIOD. */
  unsigned int num_intro_circ_launched;

  /* Replay cache tracking the REND_COOKIE found in INTRODUCE2 cell to detect
   * repeats. Clients may send INTRODUCE1 cells for the same rendezvous point
   * through two or more different introduction points; when they do, this
   * keeps us from launching multiple simultaneous attempts to connect to the
   * same rend point. */
  replaycache_t *replay_cache_rend_cookie;

  /* When is the next time we should rotate our descriptors. This is has to be
   * done at the start time of the next SRV protocol run. */
  time_t next_rotation_time;
} hs_service_state_t;

/* Representation of a service running on this tor instance. */
typedef struct hs_service_t {
  /* Onion address base32 encoded and NUL terminated. We keep it for logging
   * purposes so we don't have to build it everytime. */
  char onion_address[HS_SERVICE_ADDR_LEN_BASE32 + 1];

  /* Hashtable node: use to look up the service by its master public identity
   * key in the service global map. */
  HT_ENTRY(hs_service_t) hs_service_node;

  /* Service state which contains various flags and counters. */
  hs_service_state_t state;

  /* Key material of the service. */
  hs_service_keys_t keys;

  /* Configuration of the service. */
  hs_service_config_t config;

  /* Current descriptor. */
  hs_service_descriptor_t *desc_current;
  /* Next descriptor. */
  hs_service_descriptor_t *desc_next;

  /* XXX: Credential (client auth.) #20700. */

} hs_service_t;

/* For the service global hash map, we define a specific type for it which
 * will make it safe to use and specific to some controlled parameters such as
 * the hashing function and how to compare services. */
typedef HT_HEAD(hs_service_ht, hs_service_t) hs_service_ht;

/* API */

/* Global initializer and cleanup function. */
void hs_service_init(void);
void hs_service_free_all(void);

/* Service new/free functions. */
hs_service_t *hs_service_new(const or_options_t *options);
void hs_service_free(hs_service_t *service);

unsigned int hs_service_get_num_services(void);
void hs_service_stage_services(const smartlist_t *service_list);
int hs_service_load_all_keys(void);
void hs_service_lists_fnames_for_sandbox(smartlist_t *file_list,
                                         smartlist_t *dir_list);
int hs_service_set_conn_addr_port(const origin_circuit_t *circ,
                                  edge_connection_t *conn);

void hs_service_dir_info_changed(void);
void hs_service_run_scheduled_events(time_t now);
void hs_service_circuit_has_opened(origin_circuit_t *circ);
int hs_service_receive_intro_established(origin_circuit_t *circ,
                                         const uint8_t *payload,
                                         size_t payload_len);
int hs_service_receive_introduce2(origin_circuit_t *circ,
                                  const uint8_t *payload,
                                  size_t payload_len);

void hs_service_intro_circ_has_closed(origin_circuit_t *circ);

#ifdef HS_SERVICE_PRIVATE

#ifdef TOR_UNIT_TESTS

/* Useful getters for unit tests. */
STATIC unsigned int get_hs_service_map_size(void);
STATIC int get_hs_service_staging_list_size(void);
STATIC hs_service_ht *get_hs_service_map(void);
STATIC hs_service_t *get_first_service(void);

/* Service accessors. */
STATIC hs_service_t *find_service(hs_service_ht *map,
                                  const ed25519_public_key_t *pk);
STATIC void remove_service(hs_service_ht *map, hs_service_t *service);
STATIC int register_service(hs_service_ht *map, hs_service_t *service);
/* Service introduction point functions. */
STATIC hs_service_intro_point_t *service_intro_point_new(
                                         const extend_info_t *ei,
                                         unsigned int is_legacy);
STATIC void service_intro_point_free(hs_service_intro_point_t *ip);
STATIC void service_intro_point_add(digest256map_t *map,
                                    hs_service_intro_point_t *ip);
STATIC void service_intro_point_remove(const hs_service_t *service,
                                       const hs_service_intro_point_t *ip);
STATIC hs_service_intro_point_t *service_intro_point_find(
                                 const hs_service_t *service,
                                 const ed25519_public_key_t *auth_key);
STATIC hs_service_intro_point_t *service_intro_point_find_by_ident(
                                         const hs_service_t *service,
                                         const hs_ident_circuit_t *ident);
/* Service descriptor functions. */
STATIC hs_service_descriptor_t *service_descriptor_new(void);
STATIC hs_service_descriptor_t *service_desc_find_by_intro(
                                         const hs_service_t *service,
                                         const hs_service_intro_point_t *ip);
/* Helper functions. */
STATIC void get_objects_from_ident(const hs_ident_circuit_t *ident,
                                   hs_service_t **service,
                                   hs_service_intro_point_t **ip,
                                   hs_service_descriptor_t **desc);
STATIC const node_t *
get_node_from_intro_point(const hs_service_intro_point_t *ip);
STATIC int can_service_launch_intro_circuit(hs_service_t *service,
                                            time_t now);
STATIC int intro_point_should_expire(const hs_service_intro_point_t *ip,
                                     time_t now);
STATIC void run_housekeeping_event(time_t now);
STATIC void rotate_all_descriptors(time_t now);
STATIC void build_all_descriptors(time_t now);
STATIC void update_all_descriptors(time_t now);
STATIC void run_upload_descriptor_event(time_t now);

STATIC char *
encode_desc_rev_counter_for_state(const hs_service_descriptor_t *desc);

STATIC void service_descriptor_free(hs_service_descriptor_t *desc);

STATIC uint64_t
check_state_line_for_service_rev_counter(const char *state_line,
                                    const ed25519_public_key_t *blinded_pubkey,
                                    int *service_found_out);

STATIC int
write_address_to_file(const hs_service_t *service, const char *fname_);

STATIC void upload_descriptor_to_all(const hs_service_t *service,
                                     hs_service_descriptor_t *desc);

STATIC void service_desc_schedule_upload(hs_service_descriptor_t *desc,
                                         time_t now,
                                         int descriptor_changed);

STATIC int service_desc_hsdirs_changed(const hs_service_t *service,
                                const hs_service_descriptor_t *desc);

#endif /* defined(TOR_UNIT_TESTS) */

#endif /* defined(HS_SERVICE_PRIVATE) */

#endif /* !defined(TOR_HS_SERVICE_H) */

