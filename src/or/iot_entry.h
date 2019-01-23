/*
 * iot_entry.h
 *
 *  Created on: 23.01.2019
 *      Author: markus
 */

#ifndef SRC_OR_IOT_ENTRY_H_
#define SRC_OR_IOT_ENTRY_H_

#include "or.h"

/**
 * IoT Entry
 * Process incoming relay split cell, i.e., start buffering data coming from
 * the client.
 */
void iot_process_relay_split(circuit_t *circ);

/**
 * IoT Entry
 * Relay Pre Ticket coming from the DHS to the IoT Device.
 */
void iot_process_relay_pre_ticket(circuit_t *circ, size_t length,
	                     const uint8_t *payload);

/**
 * IoT Entry
 * Relay Ticket coming from the DHS to the IoT Device. Furthermore, split the
 * circuit for later joining.
 */
void iot_process_relay_ticket(circuit_t *circ, size_t length,
	                     const uint8_t *payload);

void
iot_process_relay_fast_ticket(circuit_t *circ, size_t length,
		const uint8_t *payload);

/**
 * IoT Entry
 * Handle IoT INFO coming from the IoT Device in order to allow relaying incoming
 * tickets to the correct IoT Device.
 */
void iot_info(or_connection_t *conn, const var_cell_t *cell);

/**
 * IoT Entry
 * Remove the IoT INFO from our list, e.g., when the connection to the IoT Device
 * is closed.
 */
void iot_remove_connected_iot (or_connection_t *conn);

/**
 * IoT Entry
 * Join the circuit formerly split and allow the IoT Device to communicate with
 * the client.
 */
void iot_join(or_connection_t *conn, const var_cell_t *cell);

#endif /* SRC_OR_IOT_ENTRY_H_ */
