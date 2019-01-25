/*
 * iot_delegation.h
 *
 *  Created on: 23.01.2019
 *      Author: markus
 */

#ifndef SRC_OR_IOT_DELEGATION_H_
#define SRC_OR_IOT_DELEGATION_H_

#include "hs_service.h"

int
iot_circ_launch_entry_point(entry_connection_t *conn, uint8_t handover);

void
iot_client_entry_handover_circuit_has_opened(origin_circuit_t *circ);

/**
 * Client on fast access without DHS.
 * Called when circuit to Entry Node is built.
 */
int iot_client_entry_circuit_has_opened(origin_circuit_t *circ);

/**
 * DHS
 * Set information about the chosen IoT Entry in circ info.
 */
int iot_set_circ_info(const hs_service_t *hs, iot_circ_info_t *info);

/**
 * DHS
 * Send the ticket to the IoT Device (via IoT Entry).
 */
void iot_ticket_send(origin_circuit_t *circ, uint8_t type);

/**
 * DHS
 * Inform the IoT Entry about the later split to ensure that it buffers data
 * coming from the client.
 */
void iot_inform_split(origin_circuit_t *circ);

void
iot_delegation_print_measurements(circuit_t *circ);

#endif /* SRC_OR_IOT_DELEGATION_H_ */
