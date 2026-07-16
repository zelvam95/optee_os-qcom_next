/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QCOM_PAS_PRIV_H
#define __QCOM_PAS_PRIV_H

#include <pas_mbn_parser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Per-session slots keyed by pas_id, shared between the command dispatch
 * (qcom_pas.c) and the authentication backend (pas_auth.c). Each slot holds
 * a TEE-private copy of the INIT_IMAGE metadata so the REE cannot alter it
 * between INIT_IMAGE and AUTH_AND_RESET.
 */
#define PAS_MD_SLOTS	8U

struct pas_md_slot {
	void *meta_data;
	size_t meta_data_size;
	uint32_t pas_id;
	bool used;
	struct pas_mbn mbn;
	/*
	 * True once pas_mbn_parse() has located a table for this slot and,
	 * on secure-boot devices, the metadata has been signature-
	 * authenticated. Gates AUTH_AND_RESET.
	 */
	bool hash_table_valid;
};

struct qcom_pas_session {
	struct pas_md_slot slots[PAS_MD_SLOTS];
};

#endif /* __QCOM_PAS_PRIV_H */
