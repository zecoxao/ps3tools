/*
* Copyright (c) 2011-2013 by naehrwert
* Copyright (c) 2011-2012 by Youness Alaoui <kakaroto@kakaroto.homelinux.net>
* This file is released under the GPLv2.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "types.h"
#include "util.h"
#include "elf.h"
#include "sce.h"
#include "sce_inlines.h"
#include "keys.h"
#include "aes.h"
#include "sha1.h"
#include "ecdsa.h"
#include "tables.h"
#include "config.h"
#include "zlib.h"
#include "self.h"
#include "np.h"

void _print_cert_file_header(FILE *fp, cert_file_header_t *h)
{
	const s8 *name;

	fprintf(fp, "[*] Certified File Header:\n");
	fprintf(fp, " Magic           0x%08X [%s]\n", _ES32(h->magic), (_ES32(h->magic) == CF_MAGIC ? "OK" : "ERROR"));
	fprintf(fp, " Version         0x%08X\n", _ES32(h->version));
	fprintf(fp, " Attribute       0x%04X [%s]\n", _ES16(h->attribute), (_ES16(h->attribute) == ATTRIBUTE_FAKE_CERTIFIED_FILE ? "FAKE" : "REAL"));

	name = _get_name(_cert_file_categories, _ES16(h->category));
	if(name != NULL)
	{
		fprintf(fp, " Category        ");
		_PRINT_RAW(fp, "0x%04X ", _ES16(h->category));
		fprintf(fp, "[%s]\n", name);
	}
	else
		fprintf(fp, " Category        0x%04X\n", _ES16(h->category));

	fprintf(fp, " Ext Header Size 0x%08X\n", _ES32(h->ext_header_size));
	fprintf(fp, " File Offset     0x%016llX\n", _ES64(h->file_offset));
	fprintf(fp, " File Size       0x%016llX\n", _ES64(h->file_size));
}

void _print_encryption_root_header(FILE *fp, encryption_root_header_t *erh)
{
	fprintf(fp, "[*] Encryption Root Header:\n");
	_hexdump(fp, " Key", 0, erh->key, ENCRYPTION_ROOT_KEY_LEN, FALSE);
	_hexdump(fp, "    ", 0, erh->key_pad, ENCRYPTION_ROOT_KEY_LEN, FALSE);
	_hexdump(fp, " IV ", 0, erh->iv, ENCRYPTION_ROOT_IV_LEN, FALSE);
	_hexdump(fp, "    ", 0, erh->iv_pad, ENCRYPTION_ROOT_IV_LEN, FALSE);
}

void _print_certification_header(FILE *fp, certification_header_t *ch)
{
	const s8 *sign_algo;
		sign_algo = _get_name(_sign_algorithms, _ES32(ch->sign_algorithm));

	
	fprintf(fp, "[*] Certification Header:\n");
	fprintf(fp, " Signature Input Length 0x%016llX\n", _ES64(ch->sig_input_length));
	if(sign_algo != NULL)
	{
		fprintf(fp, " Sign Algorithm         ");
		_PRINT_RAW(fp, "0x%08X ", _ES32(ch->sign_algorithm));
		fprintf(fp, "[%s]\n", sign_algo);
	}
	else
		fprintf(fp, " Sign Algorithm         0x%08X\n", _ES32(ch->sign_algorithm));
	fprintf(fp, " Segment Cert Number    0x%08X\n", _ES32(ch->section_count));
	fprintf(fp, " Key Count              0x%08X\n", _ES32(ch->key_count));
	fprintf(fp, " Optional Header Size   0x%08X\n", _ES32(ch->opt_header_size));
	fprintf(fp, " unknown_1              0x%08X\n", _ES32(ch->unknown_1));
	fprintf(fp, " unknown_2              0x%08X\n", _ES32(ch->unknown_2));
}

static void _print_segment_cert_header_entry_names(FILE *fp)
{
	fprintf(fp, "[*] Segment Certification Headers:\n");
	fprintf(fp, " Idx Offset   Size     SegmentType SegmentId SignAlgorithm Sig EncAlgorithm Key IV CompAlgorithm\n");
}

void _print_segment_cert_header(FILE *fp, segment_certification_header_t *sch, u32 idx)
{
	const s8 *name;
	name = _get_name(_msh_types, _ES32(sch->segment_type));

	fprintf(fp, " %03d %08llX %08llX %s        %02X        ", 
		idx, _ES64(sch->data_offset), _ES64(sch->data_size), name, _ES32(sch->segment_id));

	if(_ES32(sch->sign_algorithm) == SIGN_ALGORITHM_SHA1_HMAC)
		fprintf(fp, "[SHA1-HMAC]   %02X  ", _ES32(sch->signature_index));

	else if(_ES32(sch->sign_algorithm) == SIGN_ALGORITHM_SHA1)
		fprintf(fp, "[SHA1]        %02X  ", _ES32(sch->signature_index));

	else
		fprintf(fp, "[UNSIGNED]    --  ");

	if(_ES32(sch->enc_algorithm) == ENC_ALGORITHM_AES128_CTR)
		fprintf(fp, "[AES128-CTR] %02X  %02X ", _ES32(sch->key_index), _ES32(sch->iv_index));
	else
		fprintf(fp, "[PLAIN]      --  -- ");

	if(_ES32(sch->comp_algorithm) == COMP_ALGORITHM_ZLIB)
		fprintf(fp, "[ZLIB]\n");
	else
		fprintf(fp, "[PLAIN]\n");
}

void _print_sce_file_keys(FILE *fp, sce_buffer_ctxt_t *ctxt)
{
	u32 i;

	//Get start of keys.
	u8 *keys = (u8 *)ctxt->metash + sizeof(segment_certification_header_t) * _ES32(ctxt->metah->section_count);

	fprintf(fp, "[*] SCE File Keys:\n");
	for(i = 0; i < _ES32(ctxt->metah->key_count); i++)
	{
		fprintf(fp, " %02X:", i);
		_hexdump(fp, "", i, keys+i*0x10, 0x10, FALSE);
	}
}

void _print_sce_signature(FILE *fp, signature_t *sig)
{
	fprintf(fp, "[*] Signature Info:\n");
	_hexdump(fp, " R", 0, sig->r, SIGNATURE_R_SIZE, FALSE);
	_hexdump(fp, " S", 0, sig->s, SIGNATURE_S_SIZE, FALSE);
}

void _print_sce_signature_status(FILE *fp, sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	u8 hash[0x14];
	u8 Q[0x28];
	u8 K[0x14];
	u8 zero_buf[0x14];
	keyset_t *ks = NULL;

	//Check if a keyset is provided.
	if(keyset == NULL)
	{
		//Get previously used keyset
		ks = get_used_keyset();
	}
	else
	{
		//Use the provided keyset.
		ks = keyset_from_buffer(keyset);
	}
	
	if(ks != NULL)
	{
		//Generate header hash.
		sha1(ctxt->scebuffer, (size_t)(_ES64(ctxt->metah->sig_input_length)), hash);
		_hexdump(fp, " H", 0, hash, 0x14, FALSE);
	
		//get curve params
		u8 *ec_p = (u8 *)malloc(sizeof(u8) * 20);
		u8 *ec_a = (u8 *)malloc(sizeof(u8) * 20);
		u8 *ec_b = (u8 *)malloc(sizeof(u8) * 20);
		u8 *ec_N = (u8 *)malloc(sizeof(u8) * 21);
		u8 *ec_Gx = (u8 *)malloc(sizeof(u8) * 20);
		u8 *ec_Gy = (u8 *)malloc(sizeof(u8) * 20);
		memset(ec_p, 0, 20);
		memset(ec_a, 0, 20);
		memset(ec_b, 0, 20);
		memset(ec_N, 0, 21);
		memset(ec_Gx, 0, 20);
		memset(ec_Gy, 0, 20);
		//Print curve order N
		if (ecdsa_get_params(ks->ctype, ec_p, ec_a, ec_b, ec_N, ec_Gx, ec_Gy) == 0)
			_hexdump (fp, " N", 0, ec_N + 1, 20, FALSE);

		//Set ecdsa params
		ecdsa_set_curve(ks->ctype);
		ecdsa_set_pub(ks->pub);

		//Validate private key and calculate K
		ec_priv_to_pub(ks->priv, Q);
		get_m(ctxt->sig->r, ctxt->sig->s, hash, ks->priv, K);
		if (memcmp(ks->pub, Q, sizeof(Q)) == 0)
			_hexdump (fp, " K", 0, K, 0x14, FALSE);

		//Validate the signature.
		memset(zero_buf, 0, sizeof(zero_buf));
		if ((memcmp(ctxt->sig->r, zero_buf, sizeof(zero_buf)) == 0) || (memcmp(ctxt->sig->s, zero_buf, sizeof(zero_buf)) == 0))
			fprintf(fp, "[*] Signature status: FAIL\n");
		else
			fprintf(fp, "[*] Signature status: %s\n", (ecdsa_verify(hash, ctxt->sig->r, ctxt->sig->s) == TRUE ? "OK" : "FAIL"));
	}
	else
		fprintf(fp, "[*] Signature status: N/A\n");
}

static sce_buffer_ctxt_t *_sce_create_ctxt()
{
	sce_buffer_ctxt_t *res;

	if((res = (sce_buffer_ctxt_t *)malloc(sizeof(sce_buffer_ctxt_t))) == NULL)
		return NULL;

	memset(res, 0, sizeof(sce_buffer_ctxt_t));

	res->scebuffer = NULL;
	res->mdec = TRUE;

	//Allocate Cert file header.
	res->cfh = (cert_file_header_t *)malloc(sizeof(cert_file_header_t));
	memset(res->cfh, 0, sizeof(cert_file_header_t));

	//Allocate encryption root header and certification header (with random key/iv).
	res->erh = (encryption_root_header_t *)malloc(sizeof(encryption_root_header_t));
	_fill_rand_bytes(res->erh->key, 0x10);
	memset(res->erh->key_pad, 0, 0x10);
	_fill_rand_bytes(res->erh->iv, 0x10);
	memset(res->erh->iv_pad, 0, 0x10);
	//Allocate certification header.
	res->metah = (certification_header_t *)malloc(sizeof(certification_header_t));
	//memset(res->metah, 0, sizeof(certification_header_t));
	//Allocate signature.
	res->sig = (signature_t *)malloc(sizeof(signature_t));

	res->makeself = NULL;

	return res;
}

sce_buffer_ctxt_t *sce_create_ctxt_from_buffer(u8 *scebuffer)
{
	sce_buffer_ctxt_t *res;

	if((res = (sce_buffer_ctxt_t *)malloc(sizeof(sce_buffer_ctxt_t))) == NULL)
		return NULL;

	memset(res, 0, sizeof(sce_buffer_ctxt_t));

	res->scebuffer = scebuffer;
	res->mdec = FALSE;

	//Set pointer to Cert file header.
	res->cfh = (cert_file_header_t *)scebuffer;

	//Set pointers to file category specific headers.
	switch(_ES16(res->cfh->category))
	{
		case CF_CATEGORY_SELF:
		{
			//Signed ELF header.
			res->self.selfh = (signed_elf_header_t *)(res->scebuffer + sizeof(cert_file_header_t));

			//Program indentification header.
			res->self.ai = (program_identification_header_t *)(res->scebuffer + _ES64(res->self.selfh->program_identification_header_offset));

			//Segment ext header.
			if (_ES64(res->self.selfh->segment_ext_header_offset) != 0)
			{
				res->self.si = (segment_ext_header_t *)(res->scebuffer + _ES64(res->self.selfh->segment_ext_header_offset));
			}
			else
				res->self.si = 0;

			//Section ext header.
			if(_ES64(res->self.selfh->section_ext_header_offset) != 0)
			{
				res->self.sv = (section_ext_header_t *)(res->scebuffer + _ES64(res->self.selfh->section_ext_header_offset));
			}
			else
				res->self.sv = 0;

			//Get pointers to all supplemental headers.
			if ((_ES64(res->self.selfh->supplemental_header_offset)) != 0)
			{
				u32 len = (u32)(_ES64(res->self.selfh->supplemental_header_size));
				if(len > 0)
				{
					u8 *ptr = res->scebuffer + _ES64(res->self.selfh->supplemental_header_offset);
					res->self.cis = list_create();

					while(len > 0)
					{
						supplemental_header_t *sppl_hdr = (supplemental_header_t *)ptr;
						ptr += _ES32(sppl_hdr->size);
						len -= _ES32(sppl_hdr->size);
						list_add_back(res->self.cis, sppl_hdr);
					}
				}
			}
			else
				res->self.cis = NULL;
		}
		break;
	case CF_CATEGORY_RVK:
		//TODO
		break;
	case CF_CATEGORY_PKG:
		//TODO
		break;
	case CF_CATEGORY_SPP:
		//TODO
		break;
	default:
		free(res);
		return NULL;
		break;
	}

	//Set pointers to metadata headers.
	res->erh = (encryption_root_header_t *)(scebuffer + sizeof(cert_file_header_t) + _ES32(res->cfh->ext_header_size));
	res->metah = (certification_header_t *)((u8 *)res->erh + sizeof(encryption_root_header_t));
	res->metash = (segment_certification_header_t *)((u8 *)res->metah + sizeof(certification_header_t));

	return res;
}

sce_buffer_ctxt_t *sce_create_ctxt_build_self(u8 *elf, u32 elf_len)
{
	sce_buffer_ctxt_t *res;

	if((res = _sce_create_ctxt()) == NULL)
		return NULL;

	res->cfh->magic = _ES32(CF_MAGIC);
	res->cfh->version = _ES32(CF_VERSION_2);
	res->cfh->category = _ES16(CF_CATEGORY_SELF);

	//Allocate SELF header.
	res->self.selfh = (signed_elf_header_t *)malloc(sizeof(signed_elf_header_t));
	memset(res->self.selfh, 0, sizeof(signed_elf_header_t));
	res->self.selfh->version = _ES64(SELF_VERSION_3);
	//Allocate program identification header.
	res->self.ai = (program_identification_header_t *)malloc(sizeof(program_identification_header_t));
	memset(res->self.ai, 0, sizeof(program_identification_header_t));
	//Section ext header.
	res->self.sv = (section_ext_header_t *)malloc(sizeof(section_ext_header_t));
	//Create control info list.
	res->self.cis = list_create();
	//Create optional headers list.
	res->self.ohs = list_create();

	//Makeself context.
	res->makeself = (makeself_ctxt_t *)malloc(sizeof(makeself_ctxt_t));
	memset(res->makeself, 0, sizeof(makeself_ctxt_t));
	//ELF buffer.
	res->makeself->elf = elf;
	res->makeself->elf_len = elf_len;

	//Section list.
	res->secs = list_create();

	return res;
}

void sce_add_data_section(sce_buffer_ctxt_t *ctxt, void *buffer, u32 size, bool may_compr)
{
	sce_section_ctxt_t *sctxt = (sce_section_ctxt_t *)malloc(sizeof(sce_section_ctxt_t));
	sctxt->buffer = buffer;
	sctxt->size = size;
	sctxt->may_compr = may_compr;
	list_add_back(ctxt->secs, sctxt);
}

void sce_set_segment_certification_header(sce_buffer_ctxt_t *ctxt, u32 segment_type, bool encrypted, u32 idx)
{
	ctxt->metash[idx].segment_type = _ES32(segment_type);
	ctxt->metash[idx].segment_id = _ES32(segment_type == METADATA_SECTION_TYPE_PHDR ? idx : segment_type == METADATA_SECTION_TYPE_SHDR ? 3 : segment_type == METADATA_SECTION_TYPE_SCEV ? 0x1F : idx);
	ctxt->metash[idx].sign_algorithm = _ES32(SIGN_ALGORITHM_SHA1_HMAC);
	ctxt->metash[idx].enc_algorithm = _ES32(encrypted == TRUE ? ENC_ALGORITHM_AES128_CTR : ENC_ALGORITHM_PLAIN);
	ctxt->metash[idx].comp_algorithm = _ES32(COMP_ALGORITHM_PLAIN);
}

void sce_compress_data(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0;
	uLongf size_comp, size_bound;

	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;
		
		//Check if the section may be compressed.
		if(sec->may_compr == TRUE)
		{
			if(sec->size > 0)
			{
				size_comp = size_bound = compressBound(sec->size);
				u8 *buf = (u8 *)malloc(sizeof(u8) * size_bound);
				compress(buf, &size_comp, (const u8 *)sec->buffer, sec->size);

				if(size_comp < sec->size)
				{
					//Set compressed buffer and size.
					sec->buffer = buf;
					sec->size = size_comp;

					//Set compression algorithm in segment ext header.
					if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF && i < ctxt->makeself->si_sec_cnt)
					{
						ctxt->self.si[i].comp_algorithm = COMP_ALGORITHM_ZLIB;
						//Update size too.
						ctxt->self.si[i].size = size_comp;
					}

					//Set compression algorithm in segment certification header.
					ctxt->metash[i].comp_algorithm = _ES32(COMP_ALGORITHM_ZLIB);
				}
				else
				{
					free(buf);
					_LOG_VERBOSE("Skipped compression of section %03d (0x%08X >= 0x%08X)\n", i, (u32)size_comp, sec->size);
				}
			}
			else
				_LOG_VERBOSE("Skipped compression of section %03d (size is zero)\n", i);
		}

		i++;
	}
}

static u32 _sce_get_supplemental_header_size(sce_buffer_ctxt_t *ctxt)
{
	u32 res = 0;

	LIST_FOREACH(iter, ctxt->self.cis)
		res += _ES32(((supplemental_header_t *)iter->value)->size);

	return res;
}

static u32 _sce_get_oh_len(sce_buffer_ctxt_t *ctxt)
{
	u32 res = 0;

	LIST_FOREACH(iter, ctxt->self.ohs)
		res += _ES32(((opt_header_t *)iter->value)->size);

	return res;
}

void _sce_fixup_ctxt(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0, base_off, last_off;

	//Set section info data.
	base_off = (u32)(_ES64(ctxt->cfh->file_offset));
	LIST_FOREACH(iter, ctxt->secs)
	{
		//Save last offset.
		last_off = base_off;

		//Section offsets.
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;
		sec->offset = base_off;

		//Section infos for SELF (that are present as data sections).
		if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF && i < ctxt->makeself->si_sec_cnt)
		//{
			ctxt->self.si[i].offset = base_off;
		//	ctxt->self.si[i].size = sec->size;
		//}

		//Metadata section headers.
		ctxt->metash[i].data_offset = _ES64(base_off);
		ctxt->metash[i].data_size = _ES64(sec->size);

		//Update offset and data length.
		base_off += sec->size;
		ctxt->cfh->file_size = _ES64(base_off - _ES64(ctxt->cfh->file_offset));
		base_off = ALIGN(base_off, SCE_ALIGN);

		i++;
	}

	//Set extended header size (counted from after Cert file header).
	ctxt->cfh->ext_header_size = _ES32(ctxt->off_erh - sizeof(cert_file_header_t));

	//Set metadata header values.
	ctxt->metah->sig_input_length = _ES64(ctxt->off_sig);
	ctxt->metah->sign_algorithm = _ES32(SIGN_ALGORITHM_ECDSA);
	ctxt->metah->opt_header_size = _ES32(_sce_get_oh_len(ctxt));
	ctxt->metah->unknown_1 = _ES32(0);
	ctxt->metah->unknown_2 = _ES32(0);

	switch(_ES16(ctxt->cfh->category))
	{
	case CF_CATEGORY_SELF:
		{
			//Set header offsets.
			ctxt->self.selfh->program_identification_header_offset = _ES64(ctxt->off_self.off_ai);
			ctxt->self.selfh->elf_header_offset = _ES64(ctxt->off_self.off_ehdr);
			ctxt->self.selfh->phdr_offset = _ES64(ctxt->off_self.off_phdr);
			ctxt->self.selfh->segment_ext_header_offset = _ES64(ctxt->off_self.off_si);
			ctxt->self.selfh->section_ext_header_offset = _ES64(ctxt->off_self.off_sv);
			ctxt->self.selfh->supplemental_header_offset = _ES64(ctxt->off_self.off_cis);
			ctxt->self.selfh->supplemental_header_size = _ES64(_sce_get_supplemental_header_size(ctxt));

			//Set section headers offset in SELF header (last data section) if available.
			if(ctxt->makeself->shdrs != NULL)
				ctxt->self.selfh->shdr_offset = _ES64(last_off);
			else
				ctxt->self.selfh->shdr_offset = _ES64(0);
		}
		break;
	case CF_CATEGORY_RVK:
		//TODO
		break;
	case CF_CATEGORY_PKG:
		//TODO
		break;
	case CF_CATEGORY_SPP:
		//TODO
		break;
	default:
		//TODO
		break;
	}
}

void _sce_fixup_keys(sce_buffer_ctxt_t *ctxt)
{
	u32 i;

	//Build keys array.
	ctxt->keys_len = 0;
	ctxt->metah->key_count = _ES32(0);
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
	{
		if(_ES32(ctxt->metash[i].enc_algorithm) == ENC_ALGORITHM_AES128_CTR)
		{
			ctxt->keys_len += 0x80; //0x60 HMAC, 0x20 key/iv
			ctxt->metah->key_count += _ES32(8);
			ctxt->metash[i].signature_index = _ES32(_ES32(ctxt->metah->key_count) - 8);
			ctxt->metash[i].key_index = _ES32(_ES32(ctxt->metah->key_count) - 2);
			ctxt->metash[i].iv_index = _ES32(_ES32(ctxt->metah->key_count) - 1);
		}
		else
		{
			ctxt->keys_len += 0x60; //0x60 HMAC
			ctxt->metah->key_count += _ES32(6);
			ctxt->metash[i].signature_index = _ES32(_ES32(ctxt->metah->key_count) - 6);
			ctxt->metash[i].key_index = _ES32(0xFFFFFFFF);
			ctxt->metash[i].iv_index = _ES32(0xFFFFFFFF);
		}
	}

	//Allocate and fill keys array.
	ctxt->keys = (u8 *)malloc(sizeof(u8) * ctxt->keys_len);
	_fill_rand_bytes(ctxt->keys, ctxt->keys_len);
}

/*! Increase offset and align it. */
#define _INC_OFF_TYPE(off, type) off; \
	off += sizeof(type); \
	off = ALIGN(off, SCE_ALIGN)
#define _INC_OFF_SIZE(off, size) off; \
	off += (size); \
	off = ALIGN(off, SCE_ALIGN)

void sce_layout_ctxt(sce_buffer_ctxt_t *ctxt)
{
	u32 coff = 0;

	//Cert file header.
	ctxt->off_cfh = _INC_OFF_TYPE(coff, cert_file_header_t);

	switch(_ES16(ctxt->cfh->category))
	{
	case CF_CATEGORY_SELF:
		{
			//Signed ELF header.
			ctxt->off_self.off_selfh = _INC_OFF_TYPE(coff, signed_elf_header_t);
			//Program identification header.
			ctxt->off_self.off_ai = _INC_OFF_TYPE(coff, program_identification_header_t);
			//ELF header.
			ctxt->off_self.off_ehdr = _INC_OFF_SIZE(coff, ctxt->makeself->ehsize);
			//ELF Program headers.
			ctxt->off_self.off_phdr = _INC_OFF_SIZE(coff, ctxt->makeself->phsize);
			//Segment ext header.
			ctxt->off_self.off_si = _INC_OFF_SIZE(coff, sizeof(segment_ext_header_t) * ctxt->makeself->si_cnt);
			//Section ext header.
			ctxt->off_self.off_sv = _INC_OFF_TYPE(coff, section_ext_header_t);
			//Supplemental header.
			ctxt->off_self.off_cis = _INC_OFF_SIZE(coff, _sce_get_supplemental_header_size(ctxt));
		}
		break;
	case CF_CATEGORY_RVK:
		//TODO
		break;
	case CF_CATEGORY_PKG:
		//TODO
		break;
	case CF_CATEGORY_SPP:
		//TODO
		break;
	default:
		//TODO
		break;
	}

	//Encryption root header.
	ctxt->off_erh = _INC_OFF_TYPE(coff, encryption_root_header_t);
	//Certification header.
	ctxt->off_metah = _INC_OFF_TYPE(coff, certification_header_t);
	//Segment certification headers.
	ctxt->off_metash = _INC_OFF_SIZE(coff, _ES32(ctxt->metah->section_count) * sizeof(segment_certification_header_t));
	//Keys.
	_sce_fixup_keys(ctxt);
	ctxt->off_keys = _INC_OFF_SIZE(coff, ctxt->keys_len);

	//SELF only headers.
	if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF)
	{
		//Optional headers.
		ctxt->off_self.off_ohs = _INC_OFF_SIZE(coff, _sce_get_oh_len(ctxt));
	}

	//Signature.
	ctxt->off_sig = _INC_OFF_TYPE(coff, signature_t);

	//Header padding.
	ctxt->off_hdrpad = coff;
	coff = ALIGN(coff, HEADER_ALIGN);
	
	//Set header length.
	ctxt->cfh->file_offset = _ES64(coff);

	//Set missing values, etc.
	_sce_fixup_ctxt(ctxt);
}

static void _sce_build_header(sce_buffer_ctxt_t *ctxt)
{
	u32 i;

	//Allocate header buffer.
	ctxt->scebuffer = (u8*)malloc(sizeof(u8) * (u32)(_ES64(ctxt->cfh->file_offset)));
	memset(ctxt->scebuffer, 0, sizeof(u8) * (u32)(_ES64(ctxt->cfh->file_offset)));

	//Cert file header.
	memcpy((cert_file_header_t *)(ctxt->scebuffer + ctxt->off_cfh), ctxt->cfh, sizeof(cert_file_header_t));

	//File category dependent headers.
	switch(_ES16(ctxt->cfh->category))
	{
	case CF_CATEGORY_SELF:
		{
			//SELF header.
			memcpy((signed_elf_header_t *)(ctxt->scebuffer + ctxt->off_self.off_selfh), ctxt->self.selfh, sizeof(signed_elf_header_t));
			//Program info.
			memcpy((program_identification_header_t *)(ctxt->scebuffer + ctxt->off_self.off_ai), ctxt->self.ai, sizeof(program_identification_header_t));
			//ELF header.
			memcpy(ctxt->scebuffer + ctxt->off_self.off_ehdr, ctxt->makeself->ehdr, ctxt->makeself->ehsize);
			//ELF program headers.
			memcpy(ctxt->scebuffer + ctxt->off_self.off_phdr, ctxt->makeself->phdrs, ctxt->makeself->phsize);

			//Segment ext headers.
			u32 i;
			for(i = 0; i < ctxt->makeself->si_cnt; i++)
				_copy_es_segment_ext_header((segment_ext_header_t *)(ctxt->scebuffer + ctxt->off_self.off_si + sizeof(segment_ext_header_t) * i), &ctxt->self.si[i]);

			//Section ext header.
			memcpy((section_ext_header_t *)(ctxt->scebuffer + ctxt->off_self.off_sv), ctxt->self.sv, sizeof(section_ext_header_t));

			//Supplemental headers.
			u32 ci_base = ctxt->off_self.off_cis;
			LIST_FOREACH(iter, ctxt->self.cis)
			{
				supplemental_header_t *sppl_hdr = (supplemental_header_t *)iter->value;

				//Copy supplemental header.
				memcpy((supplemental_header_t *)(ctxt->scebuffer + ci_base), sppl_hdr, sizeof(supplemental_header_t));
				//Copy data.
				memcpy(ctxt->scebuffer + ci_base + sizeof(supplemental_header_t), ((u8 *)sppl_hdr) + sizeof(supplemental_header_t), _ES32(sppl_hdr->size) - sizeof(supplemental_header_t));

				ci_base += _ES32(sppl_hdr->size);
			}
		}
		break;
	case CF_CATEGORY_RVK:
		//TODO
		break;
	case CF_CATEGORY_PKG:
		//TODO
		break;
	case CF_CATEGORY_SPP:
		//TODO
		break;
	default:
		//TODO
		break;
	}

	//Encryption root header.
	memcpy(ctxt->scebuffer + ctxt->off_erh, ctxt->erh, sizeof(encryption_root_header_t));
	//Certification header.
	memcpy((certification_header_t *)(ctxt->scebuffer + ctxt->off_metah), ctxt->metah, sizeof(certification_header_t));
	//Segment certification headers.
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
		memcpy((segment_certification_header_t *)(ctxt->scebuffer + ctxt->off_metash + sizeof(segment_certification_header_t) * i), &ctxt->metash[i], sizeof(segment_certification_header_t));

	//Keys.
	//memcpy(ctxt->scebuffer + ctxt->off_keys, ctxt->keys, ctxt->keys_len);

	//SELF only headers.
	if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF)
	{
		//Optional headers.
		u32 oh_base = ctxt->off_self.off_ohs;
		LIST_FOREACH(iter, ctxt->self.ohs)
		{
			opt_header_t *oh = (opt_header_t *)iter->value;

			//Copy optional header.
			memcpy((opt_header_t *)(ctxt->scebuffer + oh_base), oh, sizeof(opt_header_t));
			//Copy data.
			memcpy(ctxt->scebuffer + oh_base + sizeof(opt_header_t), ((u8 *)oh) + sizeof(opt_header_t), _ES32(oh->size) - sizeof(opt_header_t));

			oh_base += _ES32(oh->size);
		}
	}
}

static bool _sce_sign_header(sce_buffer_ctxt_t *ctxt, keyset_t *ks)
{
	u8 hash[0x14];

	//Well...
	if(ks->priv == NULL || ks->pub == NULL)
		return FALSE;

	//Generate header hash.
	sha1(ctxt->scebuffer, (size_t)(_ES64(ctxt->metah->sig_input_length)), hash);

	//Generate signature.
	ecdsa_set_curve(ks->ctype);
	ecdsa_set_pub(ks->pub);
	ecdsa_set_priv(ks->priv);
	ecdsa_sign(hash, ctxt->sig->r, ctxt->sig->s);

	//Copy Signature.
	memcpy(ctxt->scebuffer + ctxt->off_sig, ctxt->sig, sizeof(signature_t));

	return TRUE;
}

static void _sce_calculate_hashes(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0, sha1_idx;

	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;

		sha1_idx = _ES32(ctxt->metash[i].signature_index);
		memset(ctxt->keys + sha1_idx * 0x10, 0, 0x20);
		sha1_hmac(ctxt->keys + (sha1_idx + 2) * 0x10, 0x40, (u8 *)sec->buffer, sec->size, ctxt->keys + sha1_idx * 0x10);

		i++;
	}
}

static bool _sce_encrypt_header(sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	u8 *ptr;
	size_t nc_off;
	u8 sblk[0x10], iv[0x10];
	keyset_t *ks;
	aes_context aes_ctxt;

	//Check if a keyset is provided.
	if(keyset == NULL)
	{
		//Try to find keyset.
		if((ks = keyset_find(ctxt)) == NULL)
			return FALSE;
	}
	else
	{
		//Use the provided keyset.
		ks = keyset_from_buffer(keyset);
	}

	//Calculate hashes.
	_sce_calculate_hashes(ctxt);

	//Copy keys.
	memcpy(ctxt->scebuffer + ctxt->off_keys, ctxt->keys, ctxt->keys_len);

	//Sign header.
	_sce_sign_header(ctxt, ks);

	//Encrypt encryption root header, segment certification headers and keys.
	nc_off = 0;
	ptr = ctxt->scebuffer + ctxt->off_metah;
	aes_setkey_enc(&aes_ctxt, ctxt->erh->key, ENCRYPTION_ROOT_KEY_BITS);
	memcpy(iv, ctxt->erh->iv, 0x10);
	aes_crypt_ctr(&aes_ctxt, 
		(size_t)(_ES64(ctxt->cfh->file_offset) - (sizeof(cert_file_header_t) + _ES32(ctxt->cfh->ext_header_size) + sizeof(encryption_root_header_t))), 
		&nc_off, iv, sblk, ptr, ptr);

	//Encrypt encryption root header.
	aes_setkey_enc(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
	ptr = ctxt->scebuffer + ctxt->off_erh;
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, sizeof(encryption_root_header_t), ks->riv, ptr, ptr);

	//Add NPDRM layer.
	if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF && _ES32(ctxt->self.ai->program_type) == PROGRAM_TYPE_NPDRM)
		if(np_encrypt_npdrm(ctxt) == FALSE)
			return FALSE;

	return TRUE;
}

static void _sce_encrypt_data(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0;
	aes_context aes_ctxt;

	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;

		size_t nc_off = 0;
		u8 buf[16];
		u8 iv[16];

		if(_ES32(ctxt->metash[i].enc_algorithm) == ENC_ALGORITHM_AES128_CTR)
		{
			memcpy(iv, ctxt->keys + _ES32(ctxt->metash[i].iv_index) * 0x10, 0x10);
			aes_setkey_enc(&aes_ctxt, ctxt->keys + _ES32(ctxt->metash[i].key_index) * 0x10, 128);
			aes_crypt_ctr(&aes_ctxt, sec->size, &nc_off, iv, buf, (u8 *)sec->buffer, (u8 *)sec->buffer);
		}

		i++;
	}
}

bool sce_encrypt_ctxt(sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	//Build SCE file header.
	_sce_build_header(ctxt);

	//Encrypt header.
	if(_sce_encrypt_header(ctxt, keyset) == FALSE)
		return FALSE;

	//Encrypt data.
	_sce_encrypt_data(ctxt);

	return TRUE;
}

bool sce_write_ctxt(sce_buffer_ctxt_t *ctxt, s8 *fname)
{
	FILE *fp;

	if((fp = fopen(fname, "wb")) == NULL)
		return FALSE;

	//Write SCE file header.
	fwrite(ctxt->scebuffer, sizeof(u8), (size_t)(_ES64(ctxt->cfh->file_offset)), fp);

	//Write SCE file sections.
	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;
		fseek(fp, sec->offset, SEEK_SET);
		fwrite(sec->buffer, sizeof(u8), sec->size, fp);
	}

	fclose(fp);

	return TRUE;
}
//refactoring needed
static bool check_for_old_algorithm(sce_buffer_ctxt_t *ctxt, keyset_t *ks)
{
	u8 *test_buf = (u8 *)malloc(sizeof(u8) * 0x50);
	u8 *test_buf2 = (u8 *)malloc(sizeof(u8) * 0x50);
	u8 *iv = (u8 *)malloc(sizeof(u8) * 0x10);
	u8 *sblk = (u8 *)malloc(sizeof(u8) * 0x10);
	u8 *ctr_iv = (u8 *)malloc(sizeof(u8) * 0x10);
	aes_context aes_ctxt;
	size_t nc_off;
	u64 sig_input_length;
	u32 sig_algo, section_count;

	memcpy(test_buf, ctxt->erh, 0x50);

	memcpy(test_buf2, test_buf, 0x50);
	nc_off = 0;
	
	memcpy(test_buf2, test_buf, 0x50);
	memcpy(iv, ks->riv, 0x10);
	aes_setkey_enc(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
	aes_crypt_ctr(&aes_ctxt, 0x40, &nc_off, iv, sblk, test_buf2, test_buf2);

	nc_off = 0;
	memcpy (ctr_iv, (test_buf2 + 0x20) ,0x10);
	aes_setkey_enc(&aes_ctxt, test_buf2, ENCRYPTION_ROOT_KEY_BITS);
	aes_crypt_ctr(&aes_ctxt, 0x10, &nc_off, ctr_iv, sblk, (test_buf2 + 0x40), (test_buf2 + 0x40));

	sig_input_length = _ES64(*(u64*)&test_buf2[0x40]);
	sig_algo = _ES32(*(u32*)&test_buf2[0x48]);
	section_count = _ES32(*(u32*)&test_buf2[0x4C]);

	if((sig_input_length < _ES64(ctxt->cfh->file_offset)) && sig_algo == 1 && section_count < 0xFF)
		return true;
	
	return false;
}

bool is_cert_header_encrypted(sce_buffer_ctxt_t *ctxt)
{
	u64 sig_input_length = _ES64(ctxt->metah->sig_input_length);
	u32 sign_algorithm = _ES32(ctxt->metah->sign_algorithm);
	u32 section_count = _ES32(ctxt->metah->section_count);
	u32 key_count = _ES32(ctxt->metah->key_count);
	if((sig_input_length < _ES64(ctxt->cfh->file_offset)) && (sign_algorithm == SIGN_ALGORITHM_ECDSA) && (section_count < 0xFF) && (key_count < 0xFF))
	{
		ctxt->mdec = TRUE;
		
		//Set start of SCE file keys.
		ctxt->keys = (u8 *)ctxt->metash + sizeof(segment_certification_header_t) * _ES32(ctxt->metah->section_count);
		ctxt->keys_len = _ES32(ctxt->metah->key_count) * 0x10;
		
		//Set SELF only headers.
		if((_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF) && (_ES64(ctxt->metah->opt_header_size) > 0))
		{	
			//Get pointers to all optional headers.
			ctxt->self.ohs = list_create();
			opt_header_t *oh = (opt_header_t *)(ctxt->keys + _ES32(ctxt->metah->key_count) * 0x10);
			list_add_back(ctxt->self.ohs, oh);
			while(_ES64(oh->next) != 0)
			{
				oh = (opt_header_t *)((u8 *)oh + _ES32(oh->size));
				list_add_back(ctxt->self.ohs, oh);
			}
			//Signature.
			ctxt->sig = (signature_t *)((u8 *)oh + _ES32(oh->size));
		}
		else
			ctxt->sig = (signature_t *)(ctxt->keys + _ES32(ctxt->metah->key_count) * 0x10);
		
		return TRUE;
	}

	return FALSE;
}

//refactoring needed
bool sce_decrypt_header(sce_buffer_ctxt_t *ctxt, u8 *metadata_info, u8 *keyset)
{
	size_t nc_off;
	u8 sblk[0x10], iv[0x10], ctr_iv[0x10];
	keyset_t *ks;
	aes_context aes_ctxt;

	//Check if provided metadata info should be used.
	if(metadata_info == NULL)
	{
		//Remove NPDRM layer.
		if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF && _ES32(ctxt->self.ai->program_type) == PROGRAM_TYPE_NPDRM)
			if(np_decrypt_npdrm(ctxt) == FALSE)
				return FALSE;

		//Check if a keyset is provided.
		if(keyset == NULL)
		{
			//Try to find keyset.
			if((ks = keyset_bruteforce(ctxt)) == NULL)
				return FALSE;

			_LOG_VERBOSE("Using keyset [%s 0x%04X %s]\n", ks->name, ks->key_revision, sce_version_to_str(ks->version));
		}
		else
		{
			//Use the provided keyset.
			ks = keyset_from_buffer(keyset);
		}

		//Decrypt metadata info.

		nc_off = 0;

		memcpy(iv, ks->riv, 0x10); //!!!
		if (check_for_old_algorithm(ctxt, ks) == false)
		{
			aes_setkey_dec(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
			aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, sizeof(encryption_root_header_t), iv, (u8 *)ctxt->erh, (u8 *)ctxt->erh);
		}
		else
		{
			aes_setkey_enc(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
			aes_crypt_ctr(&aes_ctxt, sizeof(encryption_root_header_t), &nc_off, iv, sblk, (u8 *)ctxt->erh, (u8 *)ctxt->erh);
		}
	}
	else
	{
		//Copy provided metadata info over SELF metadata.
		memcpy((u8 *)ctxt->erh, metadata_info, 0x40);
	}

	//Decrypt certification header, segment certification headers and keys.
	nc_off = 0;
	memcpy (ctr_iv, ctxt->erh->iv ,0x10);
	aes_setkey_enc(&aes_ctxt, ctxt->erh->key, ENCRYPTION_ROOT_KEY_BITS);
	aes_crypt_ctr(&aes_ctxt, 
		(size_t)(_ES64(ctxt->cfh->file_offset) - (sizeof(cert_file_header_t) + _ES32(ctxt->cfh->ext_header_size) + sizeof(encryption_root_header_t))), 
		&nc_off, ctr_iv, sblk, (u8 *)ctxt->metah, (u8 *)ctxt->metah);

	//Check if the metadata was decrypted properly.
	 if (_ES64(ctxt->metah->sig_input_length) > _ES64(ctxt->cfh->file_offset))
		return FALSE;

	//Metadata decrypted.
	ctxt->mdec = TRUE;
	
	//Set start of SCE file keys.
	ctxt->keys = (u8 *)ctxt->metash + sizeof(segment_certification_header_t) * _ES32(ctxt->metah->section_count);
	ctxt->keys_len = _ES32(ctxt->metah->key_count) * 0x10;

	//Set SELF only headers.
	if((_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF) && (_ES64(ctxt->metah->opt_header_size) > 0))
	{	
		//Get pointers to all optional headers.
		ctxt->self.ohs = list_create();
		opt_header_t *oh = (opt_header_t *)(ctxt->keys + _ES32(ctxt->metah->key_count) * 0x10);
		list_add_back(ctxt->self.ohs, oh);
		while(_ES64(oh->next) != 0)
		{
			oh = (opt_header_t *)((u8 *)oh + _ES32(oh->size));
			list_add_back(ctxt->self.ohs, oh);
		}

		//Signature.
		ctxt->sig = (signature_t *)((u8 *)oh + _ES32(oh->size));
	}
	else
		ctxt->sig = (signature_t *)(ctxt->keys + _ES32(ctxt->metah->key_count) * 0x10);

	return TRUE;
}

bool sce_decrypt_data(sce_buffer_ctxt_t *ctxt)
{
	u32 i;
	aes_context aes_ctxt;

	//Decrypt and verify segments.
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
	{
		size_t nc_off = 0;
		u8 buf[16];
		u8 iv[16];
		u8 hash[20];
		u8 temp_buf[16];
		u32 first_chunk_size;
		u8 *ptr = ctxt->scebuffer + _ES64(ctxt->metash[i].data_offset);

		//Decrypt segment.
		if((_ES64(ctxt->metash[i].data_size)) != 0)
		{
			//Only decrypt encrypted segments.
			if(_ES32(ctxt->metash[i].enc_algorithm) == ENC_ALGORITHM_AES128_CTR)
			{
				if(_ES32(ctxt->metash[i].key_index) > _ES32(ctxt->metah->key_count) - 1 || _ES32(ctxt->metash[i].iv_index) > _ES32(ctxt->metah->key_count))
					printf("[*] Warning: Skipped decryption of segment %03d (Encryption algorithm is not Plain-text, but key/iv index out of range)\n", i);
				else
				{
					memcpy(iv, ctxt->keys + _ES32(ctxt->metash[i].iv_index) * 0x10, 0x10);
					aes_setkey_enc(&aes_ctxt, ctxt->keys + _ES32(ctxt->metash[i].key_index) * 0x10, 128);

					if(((_ES64(ctxt->metash[i].data_offset))&0xF) != 0)
					{
						//Decrypt unaligned segment.
						first_chunk_size = 0x10 - (((u32)(_ES64(ctxt->metash[i].data_offset)))&0xF);

						//Decrypt the first data chunk.
						memcpy(temp_buf, ptr, 0x10);
						aes_crypt_ctr(&aes_ctxt, 0x10, &nc_off, iv, buf, temp_buf, temp_buf);
						memcpy(ptr, temp_buf, first_chunk_size);

						//Decrypt data to the end of segment.
						aes_crypt_ctr(&aes_ctxt, (size_t)(_ES64(ctxt->metash[i].data_size) - first_chunk_size), &nc_off, iv, buf, (ptr + first_chunk_size), (ptr + first_chunk_size));
					}
					else
						//Decrypt aligned segment.
						aes_crypt_ctr(&aes_ctxt, (size_t)(_ES64(ctxt->metash[i].data_size)), &nc_off, iv, buf, ptr, ptr);	
				}
			}
		}

		//Verify segment.
		if((((_ES64(ctxt->metash[i].data_offset))&0xF) != 0) && ((_ES64(ctxt->metash[i].data_size)) != 0))
		{
			//Verify unaligned segment.
			if(_ES32(ctxt->metash[i].sign_algorithm) == SIGN_ALGORITHM_SHA1_HMAC)
			{
				sha1_context sha1_hmac_ctx;
				first_chunk_size = 0x10 - (((u32)(_ES64(ctxt->metash[i].data_offset)))&0xF);

				//Transform hmac hash using the data without the first chunk.
				sha1_hmac_starts(&sha1_hmac_ctx, (ctxt->keys + _ES32(ctxt->metash[i].signature_index) * 0x10 + 0x20), 0x40 );
				sha1_hmac_update(&sha1_hmac_ctx, (ptr + first_chunk_size), (size_t)(_ES64(ctxt->metash[i].data_size) - first_chunk_size));

				//Transform hmac hash using the first chunk.
				sha1_hmac_update(&sha1_hmac_ctx, ptr, first_chunk_size);
				sha1_hmac_finish(&sha1_hmac_ctx, hash);
				memset(&sha1_hmac_ctx, 0, sizeof(sha1_context));
			}

			if(_ES32(ctxt->metash[i].sign_algorithm) == SIGN_ALGORITHM_SHA1)
			{
				sha1_context sha1_ctx;
				first_chunk_size = 0x10 - (((u32)(_ES64(ctxt->metash[i].data_offset)))&0xF);

				//Transform sha1 hash using the data without the first chunk.
				sha1_starts(&sha1_ctx);
				sha1_update(&sha1_ctx, (ptr + first_chunk_size), (size_t)(_ES64(ctxt->metash[i].data_size) - first_chunk_size));

				//Transform sha1 hash using the first chunk.
				sha1_update(&sha1_ctx, ptr, first_chunk_size);
				sha1_finish(&sha1_ctx, hash);
				memset(&sha1_ctx, 0, sizeof(sha1_context));
			}

			if(memcmp(hash, (ctxt->keys + _ES32(ctxt->metash[i].signature_index) * 0x10), 20) == 0)
				printf("[*] Verify segment %02d : OK\n", i);
			else
				printf("[*] Verify segment %02d : FAIL\n", i);
		}
		else
		{
			//Verify aligned segment.
			if(_ES32(ctxt->metash[i].sign_algorithm) == SIGN_ALGORITHM_SHA1_HMAC)
				sha1_hmac((ctxt->keys + _ES32(ctxt->metash[i].signature_index) * 0x10 + 0x20), 0x40, ptr, (size_t)(_ES64(ctxt->metash[i].data_size)), hash);

			if(_ES32(ctxt->metash[i].sign_algorithm) == SIGN_ALGORITHM_SHA1)
				sha1(ptr, (size_t)(_ES64(ctxt->metash[i].data_size)), hash);

			if(memcmp(hash, (ctxt->keys + _ES32(ctxt->metash[i].signature_index) * 0x10), 20) == 0)
				printf("[*] Verify segment %02d : OK\n", i);
			else
				printf("[*] Verify segment %02d : FAIL\n", i);
		}
	}

	return TRUE;
}

void cf_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt)
{
	//Print Cert file header.
	_print_cert_file_header(fp, ctxt->cfh);
}

void cf_ext_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt)
{
	if(_ES32(ctxt->cfh->ext_header_size) != 0)
	{
		fprintf(fp, "[*] Certified File Ext Header:\n");
	}
	
	if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF)
	{
		self_print_info(stdout, ctxt);
	}
}

void print_sce_signature_info(FILE *fp, sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	_print_sce_signature(fp, ctxt->sig);
	_print_sce_signature_status(fp, ctxt, keyset);
}

void sce_print_encrypted_info(FILE *fp, sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	u32 i;

	//Check if the metadata was decrypted.
	if(ctxt->mdec == FALSE)
		return;

	//Print encryption root header and certification header infos.
	_print_encryption_root_header(fp, ctxt->erh);
	_print_certification_header(fp, ctxt->metah);

	//Print segment certification headers info.
	_print_segment_cert_header_entry_names(fp);
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
		_print_segment_cert_header(fp, &ctxt->metash[i], i);

	//Print keys.
	_print_sce_file_keys(fp, ctxt);

	//Print optional info.
	if(_ES16(ctxt->cfh->category) == CF_CATEGORY_SELF)
		self_print_optional_info(stdout, ctxt);

	//Print signature info.
	if(ctxt->mdec == TRUE)
		print_sce_signature_info(stdout, ctxt, keyset);
}

static s8 _sce_tmp_vstr[16];
s8 *sce_version_to_str(u64 version)
{
	u32 v = version >> 32;
	sprintf(_sce_tmp_vstr, "%02X.%02X", (v & 0xFFFF0000) >> 16, v & 0x0000FFFF);
	return _sce_tmp_vstr;
}

u64 sce_str_to_version(s8 *version)
{
	u16 h, l;
	sscanf(version, "%02X.%02X", (u32 *)&h, (u32*)&l);
	return ((u64)(h << 16 | l)) << 32;
}

u64 sce_hexver_to_decver(u64 version)
{
	//TODO: hackity hack.
	s8 tmp[16];
	u32 v = version >> 32;
	u64 res;
	sprintf(tmp, "%02X%02X", (v & 0xFFFF0000) >> 16, v & 0x0000FFFF);
	sscanf(tmp, "%d", &v);
	res = v*100;

	return res;
}

u64 sce_decver_to_hexver(u64 version)
{
	//TODO: hackity hack.
	s8 tmp[16];
	u64 res;
	u32 v = (u32)version/100;
	sprintf(tmp, "%02d.%02d", v/100, v%100);
	res = sce_str_to_version(tmp);
	return res;
}

supplemental_header_t *sce_get_supplemental_header(sce_buffer_ctxt_t *ctxt, u32 type)
{
	LIST_FOREACH(iter, ctxt->self.cis)
	{
		supplemental_header_t *sppl_hdr = (supplemental_header_t *)iter->value;
		if(_ES32(sppl_hdr->type) == type)
			return sppl_hdr;
	}

	return NULL;
}

opt_header_t *sce_get_opt_header(sce_buffer_ctxt_t *ctxt, u32 type)
{
	LIST_FOREACH(iter, ctxt->self.ohs)
	{
		opt_header_t *oh = (opt_header_t *)iter->value;
		if(_ES32(oh->type) == type)
			return oh;
	}

	return NULL;
}