// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <elf32.h>
#include <elf64.h>
#include <pas_mbn_parser.h>
#include <pas_mbn_parser_priv.h>
#include <string.h>
#include <tee_internal_api.h>
#include <util.h>

/*
 * A UIE image-encryption parameter block, when present, follows the last cert
 * region in the hash segment. Its header begins with this little-endian magic.
 */
#define UIE_ENC_PARAM_MAGIC	0x514D5349	/* "ISMQ" */

/*
 * Qualcomm program-header flags encode segment type in bits 24:26 of p_flags;
 * a phdr for the MBN hash segment carries the HASH_SEGMENT type value 0x2.
 */
#define MBN_PT_FLAG_TYPE_MASK		0x07000000U
#define MBN_PT_FLAG_HASH_TYPE_MASK	0x02000000U

uint32_t pas_mbn_read_u32(const uint8_t *p)
{
	uint32_t v = 0;

	memcpy(&v, p, sizeof(v));

	return v;
}

TEE_Result pas_mbn_locate(const uint8_t *md, size_t md_size,
			  const uint8_t **segment, size_t *segment_size)
{
	const unsigned char *ident = md;
	size_t phoff = 0;
	size_t phentsize = 0;
	size_t phnum = 0;
	size_t ehdr_size = 0;
	size_t phent_min = 0;
	size_t phtab_end = 0;
	size_t hash_off = 0;
	size_t hash_end = 0;
	size_t hash_filesz = 0;
	uint32_t hash_flags = 0;
	size_t i = 0;
	bool is_64 = false;
	bool found = false;

	if (md_size < EI_NIDENT)
		return TEE_ERROR_BAD_FORMAT;

	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Both ELF classes are accepted; the MBN hash-segment header is
	 * uint32-only in either case.
	 */
	switch (ident[EI_CLASS]) {
	case ELFCLASS64:
		is_64 = true;
		ehdr_size = sizeof(Elf64_Ehdr);
		phent_min = sizeof(Elf64_Phdr);
		break;
	case ELFCLASS32:
		is_64 = false;
		ehdr_size = sizeof(Elf32_Ehdr);
		phent_min = sizeof(Elf32_Phdr);
		break;
	default:
		return TEE_ERROR_BAD_FORMAT;
	}

	if (md_size < ehdr_size)
		return TEE_ERROR_BAD_FORMAT;

	if (is_64) {
		const Elf64_Ehdr *ehdr = (const void *)md;

		phoff = ehdr->e_phoff;
		phentsize = ehdr->e_phentsize;
		phnum = ehdr->e_phnum;
	} else {
		const Elf32_Ehdr *ehdr = (const void *)md;

		phoff = ehdr->e_phoff;
		phentsize = ehdr->e_phentsize;
		phnum = ehdr->e_phnum;
	}

	if (phnum < 2 || !phoff || phentsize < phent_min)
		return TEE_ERROR_BAD_FORMAT;

	if (MUL_OVERFLOW(phentsize, phnum, &phtab_end) ||
	    ADD_OVERFLOW(phtab_end, phoff, &phtab_end) ||
	    phtab_end > md_size)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Find the phdr whose p_flags type bits mark it as the hash
	 * segment. Only p_filesz is taken from the phdr; the offset is
	 * computed below to match QTEE's PIL_parseMetadata() formula.
	 */
	for (i = 0; i < phnum; i++) {
		const uint8_t *p = md + phoff + i * phentsize;

		if (is_64) {
			const Elf64_Phdr *phdr = (const void *)p;

			hash_flags = phdr->p_flags;
			hash_filesz = phdr->p_filesz;
		} else {
			const Elf32_Phdr *phdr = (const void *)p;

			hash_flags = phdr->p_flags;
			hash_filesz = phdr->p_filesz;
		}

		if ((hash_flags & MBN_PT_FLAG_TYPE_MASK) ==
		    MBN_PT_FLAG_HASH_TYPE_MASK) {
			found = true;
			break;
		}
	}
	if (!found)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * QTEE's PIL_parseMetadata() computes the hash segment offset as
	 * ehsize + phentsize * phnum rather than trusting the phdr's
	 * p_offset: the kernel's qcom_mdt_read_metadata() repacks the
	 * metadata buffer as [ELF header + phdrs | hash segment], so
	 * p_offset (which points into the original firmware file) would run
	 * past the end of this repacked buffer.
	 */
	if (MUL_OVERFLOW(phentsize, phnum, &hash_off) ||
	    ADD_OVERFLOW(hash_off, ehdr_size, &hash_off))
		return TEE_ERROR_BAD_FORMAT;

	if (ADD_OVERFLOW(hash_off, hash_filesz, &hash_end) ||
	    hash_end > md_size || !hash_filesz)
		return TEE_ERROR_BAD_FORMAT;

	*segment = md + hash_off;
	*segment_size = hash_filesz;

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_reserve_region(const uint8_t *segment, size_t segment_size,
				  size_t *offset, size_t len,
				  const uint8_t **region, size_t *region_len)
{
	if (!len) {
		*region = NULL;
		*region_len = 0;
		return TEE_SUCCESS;
	}

	if (len > segment_size || *offset > segment_size - len)
		return TEE_ERROR_BAD_FORMAT;

	*region = segment + *offset;
	*region_len = len;
	*offset += len;

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_parse(const uint8_t *md, size_t md_size,
			 uint32_t hash_size, struct pas_mbn *out)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t oem_cert_size = 0;
	uint32_t oem_meta_size = 0;
	const uint8_t *segment = NULL;
	uint32_t oem_sig_size = 0;
	uint32_t qc_cert_size = 0;
	uint32_t qc_meta_size = 0;
	uint32_t qc_sig_size = 0;
	size_t signed_size = 0;
	uint32_t code_size = 0;
	uint32_t version = 0;
	size_t hdr_size = 0;
	size_t segment_size = 0;
	size_t offset = 0;

	if (!md || !md_size || !out || !hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(out, 0, sizeof(*out));

	res = pas_mbn_locate(md, md_size, &segment, &segment_size);
	if (res)
		return res;

	if (segment_size < MBN_HDR_SIZE_V5)
		return TEE_ERROR_BAD_FORMAT;

	version = pas_mbn_read_u32(segment + MBN_OFF_VERSION);
	switch (version) {
	case PAS_MBN_VERSION_5:
		hdr_size = MBN_HDR_SIZE_V5;
		break;
	case PAS_MBN_VERSION_6:
		hdr_size = MBN_HDR_SIZE_V6;
		break;
	default:
		EMSG("PAS auth: unsupported MBN version %"PRIu32, version);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (segment_size < hdr_size)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * The MBN header "code_size" field is the hash-table length in bytes,
	 * i.e. num_entries * hash_size (one digest per program header).
	 */
	code_size = pas_mbn_read_u32(segment + MBN_OFF_CODE_SIZE);
	qc_sig_size = pas_mbn_read_u32(segment + MBN_OFF_QC_SIG_SIZE);
	qc_cert_size = pas_mbn_read_u32(segment + MBN_OFF_QC_CERT_SIZE);
	oem_sig_size = pas_mbn_read_u32(segment + MBN_OFF_OEM_SIG_SIZE);
	oem_cert_size = pas_mbn_read_u32(segment + MBN_OFF_OEM_CERT_SIZE);
	if (version == PAS_MBN_VERSION_6) {
		qc_meta_size = pas_mbn_read_u32(segment + MBN_OFF_QC_META_SIZE);
		oem_meta_size = pas_mbn_read_u32(segment +
						 MBN_OFF_OEM_META_SIZE);
	}

	if (!code_size || code_size % hash_size)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Payload after the header:
	 *   [qc_meta][oem_meta][hash table][qc_sig][qc_cert][oem_sig][oem_cert]
	 * The signature covers the MBN header followed by
	 * [qc_meta || oem_meta || hash table], so the signed region spans the
	 * header and that payload from the segment start.
	 */
	offset = hdr_size;
	out->signed_region = segment;

	if (ADD_OVERFLOW(qc_meta_size, oem_meta_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, code_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, hdr_size, &signed_size))
		return TEE_ERROR_BAD_FORMAT;

	if (signed_size > segment_size)
		return TEE_ERROR_BAD_FORMAT;
	out->signed_region_size = signed_size;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     qc_meta_size, &out->qti_meta,
				     &out->qti_meta_size);
	if (res)
		return res;
	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     oem_meta_size, &out->oem_meta,
				     &out->oem_meta_size);
	if (res)
		return res;

	out->hash_table = segment + offset;
	out->hash_table_size = code_size;
	out->hash_size = hash_size;
	out->num_entries = code_size / hash_size;
	offset += code_size;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     qc_sig_size, &out->qti_sig,
				     &out->qti_sig_size);
	if (res)
		return res;
	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     qc_cert_size, &out->qti_certs,
				     &out->qti_certs_size);
	if (res)
		return res;
	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     oem_sig_size, &out->oem_sig,
				     &out->oem_sig_size);
	if (res)
		return res;
	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     oem_cert_size, &out->oem_certs,
				     &out->oem_certs_size);
	if (res)
		return res;

	out->version = version;

	/* Optional trailing UIE image-encryption parameter block. */
	if (offset + sizeof(uint32_t) <= segment_size &&
	    pas_mbn_read_u32(segment + offset) == UIE_ENC_PARAM_MAGIC)
		out->uie_encrypted = true;

	return TEE_SUCCESS;
}
