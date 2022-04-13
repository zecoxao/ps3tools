/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "types.h"
#include "config.h"
#include "util.h"
#include "sce.h"
#include "sce_inlines.h"
#include "self.h"
#include "elf.h"
#include "elf_inlines.h"
#include "tables.h"
#include "sha1.h"
#include "np.h"

static void _get_shdr_flags(s8 *str, u64 flags)
{
	memset(str, '-', 3);
	str[3] = 0;

	if(flags & SHF_WRITE)
		str[0] = 'W';
	if(flags & SHF_ALLOC)
		str[1] = 'A';
	if(flags & SHF_EXECINSTR)
		str[2] = 'E';
}

static void _get_phdr_flags(s8 *str, u64 flags)
{
	memset(str, '-', 3);
	str[3] = 0;

	if(flags & PF_X)
		str[0] = 'X';
	if(flags & PF_W)
		str[1] = 'W';
	if(flags & PF_R)
		str[2] = 'R';
}

s64 _get_compressed_self_diff(sce_buffer_ctxt_t *ctxt)
{
	const u8 *eident;
//	const u16 *e_type;
	bool is_fself;
	bool is_elf32;
	bool is_elf64;
	u32 i;
	s64 res = -1;

	//Check for SELF.
	if(_ES16(ctxt->cfh->category) != CF_CATEGORY_SELF)
		return -1;

	if(_ES16(ctxt->cfh->attribute) == ATTRIBUTE_FAKE_CERTIFIED_FILE)
		is_fself = TRUE;
	else
		is_fself = FALSE;

	eident = ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset);

	if(eident[EI_CLASS] == ELFCLASS32)
		is_elf32 = TRUE;
	else
		is_elf32 = FALSE;
	
	if(eident[EI_CLASS] == ELFCLASS64)
		is_elf64 = TRUE;
	else
		is_elf64 = FALSE;

//	e_type = (u16 *)(ctxt->scebuffer + (_ES64(ctxt->self.selfh->elf_header_offset)) + EI_NIDENT);

//	if(_ES16((u16)*e_type) != ET_EXEC)
//		return -1;
	
	if (_ES64(ctxt->self.selfh->shdr_offset) == 0)
		return -1;
	
	if (is_elf32)
	{
		Elf32_Ehdr *eh = (Elf32_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));
		Elf32_Phdr *ph = (Elf32_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));
		if(is_fself)
		{
			//32 fself
			if ((_ES64(ctxt->self.selfh->shdr_offset) !=0) && (_ES64(ctxt->self.selfh->shdr_offset) > _ES64(ctxt->cfh->file_offset)))
			{
				//fast method
				res = (_ES32(eh->e_shoff) - _ES64(ctxt->self.selfh->shdr_offset) +  _ES64(ctxt->cfh->file_offset));
			}
			else
			{
				segment_ext_header_t *segeh = ctxt->self.si;
				u64 pseg_end_offset;
				u64 comp_pseg_end_offset;
				u64 diff = 0;

				for(i = 0; i < _ES16(eh->e_phnum); i++)
				{
					//Handling LOADable program segments only.
					if(_ES32(ph[i].p_type) == PT_LOAD)
					{
						if(_ES32(segeh[i].comp_algorithm) != COMP_ALGORITHM_PLAIN)
						{
							pseg_end_offset = (_ES32(ph[i].p_offset)) + (_ES32(ph[i].p_filesz));
							comp_pseg_end_offset = (_ES64(segeh[i].offset)) + (_ES64(segeh[i].size));
							diff = pseg_end_offset - comp_pseg_end_offset + _ES64(ctxt->cfh->file_offset);
						}
					}
				}
				// Could be implemented better.
				if(_ES64(ctxt->self.selfh->section_ext_header_offset) != 0)
					diff -= (diff % 0x10);

				res = diff;
			}
		}
		else
		{
			//32 self
			if ((_ES64(ctxt->self.selfh->shdr_offset) !=0) && (_ES64(ctxt->self.selfh->shdr_offset) > _ES64(ctxt->cfh->file_offset)))
			{
				//fast method
				res = (_ES32(eh->e_shoff) - _ES64(ctxt->self.selfh->shdr_offset) +  _ES64(ctxt->cfh->file_offset));
			}
			else
			{
				if (ctxt->mdec != TRUE)
					return -1;

				certification_header_t *certh = ctxt->metah;
				segment_certification_header_t *segch = ctxt->metash;
				u64 pseg_diff = 0, diff = 0, distance = 0, distance_comp = 0, distance_diff = 0, elf_offset = 0, self_offset = _ES64(ctxt->cfh->file_offset);

				for(i = 0; i < _ES32(certh->section_count); i++)
				{
					//Handling program segments.
					if(_ES32(segch[i].segment_type) == METADATA_SECTION_TYPE_PHDR)
					{

						//PT_PROC_PRX_PARAM can not be compressed, cause it is a part of some another loadable segment.
						if((_ES32(segch[i].segment_type) == METADATA_SECTION_TYPE_PHDR) && _ES32(ph[(_ES32(segch[i].segment_id))].p_type) == PT_PROC_PRX_PARAM && (_ES32(segch[i].comp_algorithm) == COMP_ALGORITHM_ZLIB))
							return -1;

						//Handling LOADable program segments only.
						if(_ES32(ph[(_ES32(segch[i].segment_id))].p_type) == PT_LOAD)
						{
							distance = ((_ES32(ph[(_ES32(segch[i].segment_id))].p_offset)) - elf_offset); //distance in elf
							distance_comp = _ES64(segch[i].data_offset) - self_offset; //distance in self
							distance_diff = distance_comp - distance;
							pseg_diff = ((_ES32(ph[(_ES32(segch[i].segment_id))].p_filesz)) - (_ES64(segch[i].data_size)));

//							fprintf(stdout, " elf_offset      0x%016llX\n", elf_offset);
//							fprintf(stdout, " self_offset     0x%016llX\n", self_offset);
//							fprintf(stdout, " DIST_IN_ELF     0x%016llX\n", distance);
//							fprintf(stdout, " DIST_IN_SELF    0x%016llX\n", distance_comp);
//							fprintf(stdout, " DIST_DIFF       0x%016llX\n", distance_diff);
//							fprintf(stdout, " PSEG_DIFF       0x%016llX\n", pseg_diff);

							//update offsets.
							elf_offset = (elf_offset + distance + _ES32(ph[(_ES32(segch[i].segment_id))].p_filesz));
							self_offset =  (self_offset + distance_comp + _ES64(segch[i].data_size));

							//update difference.
							diff += (pseg_diff - distance_diff);
						}
					}

//					fprintf(stdout, " DIFFERENCE      0x%016llX\n\n", diff);
				}

				//fix difference.
				if (pseg_diff == 0)
				{
					diff = diff + distance_diff;
//					fprintf(stdout, " DIFFERENCE      0x%016llX\n\n", diff);
				}

				res = diff;
			}
		}
	}

	if (is_elf64)
	{
		Elf64_Ehdr *eh = (Elf64_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));
		Elf64_Phdr *ph = (Elf64_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));
		if(is_fself)
		{
			//64 fself
			if ((_ES64(ctxt->self.selfh->shdr_offset) !=0) && (_ES64(ctxt->self.selfh->shdr_offset) > _ES64(ctxt->cfh->file_offset)))
			{
				//fast method
				res = (_ES64(eh->e_shoff) - _ES64(ctxt->self.selfh->shdr_offset) +  _ES64(ctxt->cfh->file_offset));
			}
			else
			{
				segment_ext_header_t *segeh = ctxt->self.si;
				u64 pseg_end_offset;
				u64 comp_pseg_end_offset;
				u64 diff = 0;

				for(i = 0; i < _ES16(eh->e_phnum); i++)
				{
					//Handling LOADable program segments only.
					if(_ES32(ph[i].p_type) == PT_LOAD)
					{
						if(_ES32(segeh[i].comp_algorithm) != COMP_ALGORITHM_PLAIN)
						{
							pseg_end_offset = (_ES64(ph[i].p_offset)) + (_ES64(ph[i].p_filesz));
							comp_pseg_end_offset = (_ES64(segeh[i].offset)) + (_ES64(segeh[i].size));
							diff = pseg_end_offset - comp_pseg_end_offset + _ES64(ctxt->cfh->file_offset);
						}
					}
				}
				// Could be implemented better.
				if(_ES64(ctxt->self.selfh->section_ext_header_offset) != 0)
					diff -= (diff % 0x10);

				res = diff;
			}
		}
		else
		{
			//64 self
			if ((_ES64(ctxt->self.selfh->shdr_offset) !=0) && (_ES64(ctxt->self.selfh->shdr_offset) > _ES64(ctxt->cfh->file_offset)))
			{
				//fast method
				res = (_ES64(eh->e_shoff) - _ES64(ctxt->self.selfh->shdr_offset) +  _ES64(ctxt->cfh->file_offset));
			}
			else
			{
				if (ctxt->mdec != TRUE)
					return -1;

				certification_header_t *certh = ctxt->metah;
				segment_certification_header_t *segch = ctxt->metash;
				u64 pseg_diff = 0, diff = 0, distance = 0, distance_comp = 0, distance_diff = 0, elf_offset = 0, self_offset = _ES64(ctxt->cfh->file_offset);

				for(i = 0; i < _ES32(certh->section_count); i++)
				{
					//Handling program segments.
					if(_ES32(segch[i].segment_type) == METADATA_SECTION_TYPE_PHDR)
					{
						//PT_PROC_PRX_PARAM can not be compressed, cause it is a part of some another loadable segment.
						if((_ES32(ph[(_ES32(segch[i].segment_id))].p_type) == PT_PROC_PRX_PARAM) &&  (_ES32(segch[i].comp_algorithm) == COMP_ALGORITHM_ZLIB))
							return -1;

						//Handling LOADable program segments only.
						if (_ES32(ph[(_ES32(segch[i].segment_id))].p_type) == PT_LOAD)
						{
							distance = ((_ES64(ph[(_ES32(segch[i].segment_id))].p_offset)) - elf_offset); //distance in elf
							distance_comp = _ES64(segch[i].data_offset) - self_offset; //distance in self
							distance_diff = distance_comp - distance;
							pseg_diff = ((_ES64(ph[(_ES32(segch[i].segment_id))].p_filesz)) - (_ES64(segch[i].data_size)));

//							fprintf(stdout, " elf_offset      0x%016llX\n", elf_offset);
//							fprintf(stdout, " self_offset     0x%016llX\n", self_offset);
//							fprintf(stdout, " DIST_IN_ELF     0x%016llX\n", distance);
//							fprintf(stdout, " DIST_IN_SELF    0x%016llX\n", distance_comp);
//							fprintf(stdout, " DIST_DIFF       0x%016llX\n", distance_diff);
//							fprintf(stdout, " PSEG_DIFF       0x%016llX\n", pseg_diff);

							//update offsets.
							elf_offset = (elf_offset + distance + _ES64(ph[(_ES32(segch[i].segment_id))].p_filesz));
							self_offset =  (self_offset + distance_comp + _ES64(segch[i].data_size));

							//update difference.
							diff += (pseg_diff - distance_diff);
						}
					}
//					fprintf(stdout, " DIFFERENCE      0x%016llX\n\n", diff);
				}

				//fix difference.

					if (pseg_diff == 0)
					{
						diff = diff + distance_diff;
//						fprintf(stdout, " DIFFERENCE      0x%016llX\n\n", diff);
					}
				res = diff;
			}
		}
	}
//	fprintf(stdout, " RESULT      0x%016llX\n", res);
	return res;
}

bool _is_shstrtab_valid(u8 *shstrtab_buf, u32 shstrtab_name_offset)
{
	if (!strncmp((s8 *)(shstrtab_buf + shstrtab_name_offset), ".shstrtab", 10))
		return TRUE;

	return FALSE;
}

void _print_signed_elf_header(FILE *fp, signed_elf_header_t *h)
{
	fprintf(fp, "[*] Signed ELF Header:\n");
	fprintf(fp, " Version                    0x%016llX\n", _ES64(h->version));
	fprintf(fp, " Prog Ident Header Offset   0x%016llX\n", _ES64(h->program_identification_header_offset));
	fprintf(fp, " ELF Header Offset          0x%016llX\n", _ES64(h->elf_header_offset));
	fprintf(fp, " ELF Program Headers Offset 0x%016llX\n", _ES64(h->phdr_offset));
	
	if ((_ES64(h->shdr_offset)) != 0)
		fprintf(fp, " ELF Section Headers Offset 0x%016llX\n", _ES64(h->shdr_offset));
	else
		fprintf(fp, " ELF Section Headers Offset N/A\n");

	if ((_ES64(h->segment_ext_header_offset)) != 0)
		fprintf(fp, " Segment Ext Header Offset  0x%016llX\n", _ES64(h->segment_ext_header_offset));
	else
		fprintf(fp, " Segment Ext Header Offset  N/A\n");

	if ((_ES64(h->section_ext_header_offset)) != 0)
		fprintf(fp, " Section Ext Header Offset  0x%016llX\n", _ES64(h->section_ext_header_offset));
	else
		fprintf(fp, " Section Ext Header Offset  N/A\n");

	//SELF v.3+ members
	if (_ES64(h->version) > SELF_VERSION_2)
	{
		if ((_ES64(h->supplemental_header_offset)) != 0)
		{
			fprintf(fp, " Supplemental Header Offset 0x%016llX\n", _ES64(h->supplemental_header_offset));
			fprintf(fp, " Supplemental Header Size   0x%016llX\n", _ES64(h->supplemental_header_size));
		}
		else
		{
			fprintf(fp, " Supplemental Header Offset N/A\n");
			fprintf(fp, " Supplemental Header Size   N/A\n");
		}
	}
	//fprintf(fp, " padding             0x%016llX\n", _ES64(h->padding));
}

void _print_program_identification_header(FILE *fp, program_identification_header_t *ai)
{
	const s8 *name;

	fprintf(fp, "[*] Program Identification Header:\n");
	
	name = _get_name(_auth_ids, _ES64(ai->auth_id));
	if(name != NULL)
	{
		fprintf(fp, " Auth-ID   ");
		_PRINT_RAW(fp, "0x%016llX ", _ES64(ai->auth_id));
		fprintf(fp, "[%s]\n", name);
	}
	else
		fprintf(fp, " Auth-ID   0x%016llX\n", _ES64(ai->auth_id));
	
	name = _get_name(_vender_ids, _ES32(ai->vender_id));
	if(name != NULL)
	{
		fprintf(fp, " Vender-ID ");
		_PRINT_RAW(fp, "0x%08X ", _ES32(ai->vender_id));
		fprintf(fp, "[%s]\n", name);
	}
	else
		fprintf(fp, " Vender-ID 0x%08X\n", _ES32(ai->vender_id));
	
	vender_id_t *vender = (vender_id_t*)(&ai->vender_id);
	_PRINT_RAW(fp, " Territory 0x%02X\n", (vender->territory));
	//_PRINT_RAW(fp, " unknown_1 0x%02X\n", (vender->unknown_1));
	//_PRINT_RAW(fp, " unknown_2 0x%02X\n", (vender->unknown_2));
	_PRINT_RAW(fp, " Gos-id    0x%02X\n", (vender->gos_id));

	name = _get_name(_program_types, _ES32(ai->program_type));
	if(name != NULL)
	{
		fprintf(fp, " Type      ");
		_PRINT_RAW(fp, "0x%08X ", _ES32(ai->program_type));
		fprintf(fp, "[%s]\n", name);
	}
	
	else
		fprintf(fp, " Type      0x%08X\n", _ES32(ai->program_type));

	fprintf(fp, " Version   %s\n", sce_version_to_str(_ES64(ai->version)));
	//fprintf(fp, " padding   0x%016llX\n", _ES64(ai->padding));
}

void _print_segment_ext_header_v2_entry_names(FILE *fp)
{
	fprintf(fp, "[*] Segment Ext Header:\n");
	fprintf(fp, " Idx Offset   Size\n");
}

void _print_segment_ext_header_v3_entry_names(FILE *fp)
{
	fprintf(fp, "[*] Segment Ext Header:\n");
	fprintf(fp, " Idx Offset   Size     CompAlgorithm unk0     unk1     Encrypted\n");
}

void _print_segment_ext_header_v2_info(FILE *fp, segment_ext_header_t *si, u32 idx)
{
	fprintf(fp, " %03d %08X %08X\n", 
		idx, (u32)_ES64(si->offset), (u32)_ES64(si->size));
}

void _print_segment_ext_header_v3_info(FILE *fp, segment_ext_header_t *si, u32 idx)
{
	fprintf(fp, " %03d %08X %08X %s     %08X %08X %s\n", 
		idx, (u32)_ES64(si->offset), (u32)_ES64(si->size), _ES32(si->comp_algorithm) == COMP_ALGORITHM_ZLIB ? "[ZLIB]   " : _ES32(si->comp_algorithm) == COMP_ALGORITHM_PLAIN ? "[PLAIN]  " : "[UNKNOWN]", 
		_ES32(si->unknown_0), _ES32(si->unknown_1), _ES32(si->encrypted) == 1 ? "[YES]" : "[NO] ");
}

void _print_section_ext_header(FILE *fp, section_ext_header_t *sv)
{
	fprintf(fp, "[*] Section Ext Header:\n");
	fprintf(fp, " Header Type 0x%08X\n", _ES32(sv->header_type));
	fprintf(fp, " Present     [%s]\n", _ES32(sv->present) == SCE_VERSION_PRESENT ? "TRUE" : "FALSE");
	fprintf(fp, " Size        0x%08X\n", _ES32(sv->size));
	fprintf(fp, " unknown_3   0x%08X\n", _ES32(sv->unknown_3));
}

void _print_supplemental_header(FILE *fp, supplemental_header_t *ci)
{
	const s8 *name;
	time_t t;
	tm* aTm;

	fprintf(fp, "[*] Supplemental Header:\n");

	name = _get_name(_supplemental_header_types, _ES32(ci->type));
	if(name != NULL)
		fprintf(fp, " Type      %s\n", name);
	else
		fprintf(fp, " Type      0x%08X\n", _ES32(ci->type));

	fprintf(fp, " Size      0x%08X\n", _ES32(ci->size));
	fprintf(fp, " Next      [%s]\n", _ES64(ci->next) == 1 ? "TRUE" : "FALSE");

	switch(_ES32(ci->type))
	{
	case SPPL_HEADER_TYPE_SELF_CONTROL_FLAGS:
		_hexdump(fp, " Flags", 0, (u8 *)ci + sizeof(supplemental_header_t), _ES32(ci->size) - sizeof(supplemental_header_t), FALSE);
		break;
	case SPPL_HEADER_TYPE_ELF_DIGEST_HEADER:
		if(_ES32(ci->size) == 0x30)
		{
			ci_data_digest_30_t *dig = (ci_data_digest_30_t *)((u8 *)ci + sizeof(supplemental_header_t));
			_hexdump(fp, " Digest", 0, dig->digest, 20, FALSE);
		}
		else if(_ES32(ci->size) == 0x40)
		{
			ci_data_digest_40_t *dig = (ci_data_digest_40_t *)((u8 *)ci + sizeof(supplemental_header_t));
			_hexdump(fp, " Digest 1  ", 0, dig->digest1, 20, FALSE);
			_hexdump(fp, " Digest 2  ", 0, dig->digest2, 20, FALSE);
			if(_ES64(dig->fw_version) != 0)
				fprintf(fp, " FW Version %d [%02d.%02d]\n", (u32)_ES64(dig->fw_version), ((u32)_ES64(dig->fw_version))/10000, (((u32)_ES64(dig->fw_version))%10000)/100);
		}
		break;
	case SPPL_HEADER_TYPE_NPDRM_HEADER:
		{
			ci_data_npdrm_t *np = (ci_data_npdrm_t *)((u8 *)ci + sizeof(supplemental_header_t));
			//Was already fixed in decrypt_header.
			//_es_ci_data_npdrm(np);
			fprintf(fp, " Magic          0x%08X [%s]\n", _ES32(np->magic), (_ES32(np->magic) == NP_HEADER_MAGIC ? "OK" : "ERROR"));
			fprintf(fp, " Version        0x%08X\n", _ES32(np->version));
			
			name = _get_name(_np_drm_types, _ES32(np->drm_type));
			if(name != NULL)
			{
				fprintf(fp, " DRM Type       ");
				_PRINT_RAW(fp, "0x%08X ", _ES32(np->drm_type));
				fprintf(fp, "[%s]\n", name);
			}
			else
				fprintf(fp, " DRM Type       0x%08X\n", _ES32(np->drm_type));

			name = _get_name(_np_app_types, _ES32(np->app_type));
			if(name != NULL)
			{
				fprintf(fp, " App Type       ");
				_PRINT_RAW(fp, "0x%08X ", _ES32(np->app_type));
				fprintf(fp, "[%s]\n", name);
			}
			else
				fprintf(fp, " App Type       0x%08X\n", _ES32(np->app_type));

			fprintf(fp, " ContentID      %s\n", np->content_id);
			_hexdump(fp, " Random Pad    ", 0, np->rndpad, 0x10, FALSE);
			_hexdump(fp, " CID_FN Hash   ", 0, np->hash_cid_fname, 0x10, FALSE);
			_hexdump(fp, " CI Hash       ", 0, np->hash_ci, 0x10, FALSE);

			t = (time_t)(_ES64(np->limited_time_start) / 1000);
			aTm = localtime(&t);
			if(_ES64(np->limited_time_start) != 0)
			{
				fprintf(fp, " Validity Start ");
				_PRINT_RAW(fp, "0x%016llX ", _ES64(np->limited_time_start));
				fprintf(fp, "[%04d/%02d/%02d %02d:%02d:%02d]\n",aTm->tm_year+1900, aTm->tm_mon+1, aTm->tm_mday, aTm->tm_hour, aTm->tm_min, aTm->tm_sec);
			}
			else
			{
				fprintf(fp, " Validity Start ");
				_PRINT_RAW(fp, "0x%016llX ", _ES64(np->limited_time_start));
				fprintf(fp, "[Unlimited]\n");	
			}

			t = (time_t)(_ES64(np->limited_time_end) / 1000);
			aTm = localtime(&t);
			if(_ES64(np->limited_time_end) != 0)
			{
				fprintf(fp, " Validity End   ");
				_PRINT_RAW(fp, "0x%016llX ", _ES64(np->limited_time_end));
				fprintf(fp, "[%04d/%02d/%02d %02d:%02d:%02d]\n",aTm->tm_year+1900, aTm->tm_mon+1, aTm->tm_mday, aTm->tm_hour, aTm->tm_min, aTm->tm_sec);
			}
			else
			{
				fprintf(fp, " Validity End   ");
				_PRINT_RAW(fp, "0x%016llX ", _ES64(np->limited_time_end));
				fprintf(fp, "[Unlimited]\n");	
			}
		}
		break;
	}
}

static void _print_cap_flags_flags(FILE *fp, oh_data_cap_flags_t *cf)
{
	if(_ES64(cf->flags) & 0x01)
		fprintf(fp, "0x01 ");
	if(_ES64(cf->flags) & 0x02)
		fprintf(fp, "0x02 ");
	if(_ES64(cf->flags) & 0x04)
		fprintf(fp, "0x04 ");
	if(_ES64(cf->flags) & CAP_FLAG_DEH)
		fprintf(fp, "DEH ");
	if(_ES64(cf->flags) & CAP_FLAG_DEX)
		fprintf(fp, "DEX ");
	if(_ES64(cf->flags) & CAP_FLAG_CEX)
		fprintf(fp, "CEX ");
	if(_ES64(cf->flags) & CAP_FLAG_ARCADE)
		fprintf(fp, "ARCADE ");
}

void _print_opt_header(FILE *fp, opt_header_t *oh)
{
	const s8 *name;

	fprintf(fp, "[*] Optional Header\n");

	name = _get_name(_optional_header_types, _ES32(oh->type));
	if(name != NULL)
		fprintf(fp, " Type      %s\n", name);
	else
		fprintf(fp, " Type      0x%08X\n", _ES32(oh->type));

	fprintf(fp, " Size      0x%08X\n", _ES32(oh->size));
	fprintf(fp, " Next      [%s]\n", _ES64(oh->next) == 1 ? "TRUE" : "FALSE");

	switch(_ES32(oh->type))
	{
	case OPT_HEADER_TYPE_CAP_FLAGS:
		{
			if (_ES32(oh->size) == 0x30)
			{
				oh_data_cap_flags_t *cf = (oh_data_cap_flags_t *)((u8 *)oh + sizeof(opt_header_t));

				_IF_RAW(_hexdump(fp, " Flags", 0, (u8 *)cf, sizeof(oh_data_cap_flags_t), FALSE));

			//	_es_oh_data_cap_flags(cf);

				fprintf(fp, " unknown_3 0x%016llX\n", _ES64(cf->unk3));
				fprintf(fp, " unknown_4 0x%016llX\n", _ES64(cf->unk4));

				fprintf(fp, " Flags     0x%016llX [ ", _ES64(cf->flags));
				_print_cap_flags_flags(fp, cf);
				fprintf(fp, "]\n");

				fprintf(fp, " unknown_6 0x%08X\n", _ES32(cf->unk6));
				fprintf(fp, " unknown_7 0x%08X\n", _ES32(cf->unk7));
			}
			else
			{
				u8 *h1 = (u8 *)oh + sizeof(opt_header_t);
				_hexdump(fp, " Flags", 0, h1, _ES32(oh->size) - sizeof(opt_header_t), FALSE);
			}
		}
		break;
	case OPT_HEADER_TYPE_INDIV_SEED:
		{
			u8 *is = (u8 *)oh + sizeof(opt_header_t);
			_hexdump(fp, " Seed", 0, is, _ES32(oh->size) - sizeof(opt_header_t), FALSE);
		}
		break;
	case OPT_HEADER_TYPE_CONTROL_FLAGS:
		{
			u8 *ctrlf = (u8 *)oh + sizeof(opt_header_t);
			_hexdump(fp, " Flags", 0, ctrlf, _ES32(oh->size) - sizeof(opt_header_t), FALSE);
		}
		break;
	}
}

void _print_elf32_ehdr(FILE *fp, Elf32_Ehdr *h)
{
	const s8 *name;

	fprintf(fp, "[*] ELF32 Header:\n");

	name = _get_name(_e_types, _ES16(h->e_type));
	if(name != NULL)
		fprintf(fp, " Type                   [%s]\n", name);
	else
		fprintf(fp, " Type                   0x%04X\n", _ES16(h->e_type));

	name = _get_name(_e_machines, _ES16(h->e_machine));
	if(name != NULL)
		fprintf(fp, " Machine                [%s]\n", name);
	else
		fprintf(fp, " Machine                0x%04X\n", _ES16(h->e_machine));
	
	fprintf(fp, " Version                0x%08X\n", _ES32(h->e_version));
	fprintf(fp, " Entry                  0x%08X\n", _ES32(h->e_entry));
	fprintf(fp, " Program Headers Offset 0x%08X\n", _ES32(h->e_phoff));
	fprintf(fp, " Section Headers Offset 0x%08X\n", _ES32(h->e_shoff));
	fprintf(fp, " Flags                  0x%08X\n", _ES32(h->e_flags));
	fprintf(fp, " Program Headers Count  %04d\n", _ES16(h->e_phnum));
	fprintf(fp, " Section Headers Count  %04d\n", _ES16(h->e_shnum));
	fprintf(fp, " SH String Table Index  %04d\n", _ES16(h->e_shstrndx));
}

void _print_elf64_ehdr(FILE *fp, Elf64_Ehdr *h)
{
	const s8 *name;

	fprintf(fp, "[*] ELF64 Header:\n");

	name = _get_name(_e_types, _ES16(h->e_type));
	if(name != NULL)
		fprintf(fp, " Type                   [%s]\n", name);
	else
		fprintf(fp, " Type                   0x%04X\n", _ES16(h->e_type));

	name = _get_name(_e_machines, _ES16(h->e_machine));
	if(name != NULL)
		fprintf(fp, " Machine                [%s]\n", name);
	else
		fprintf(fp, " Machine                0x%04X\n", _ES16(h->e_machine));
	
	fprintf(fp, " Version                0x%08X\n", _ES32(h->e_version));
	fprintf(fp, " Entry                  0x%016llX\n", _ES64(h->e_entry));
	fprintf(fp, " Program Headers Offset 0x%016llX\n", _ES64(h->e_phoff));
	fprintf(fp, " Section Headers Offset 0x%016llX\n", _ES64(h->e_shoff));
	fprintf(fp, " Flags                  0x%08X\n", _ES32(h->e_flags));
	fprintf(fp, " Program Headers Count  %04d\n", _ES16(h->e_phnum));
	fprintf(fp, " Section Headers Count  %04d\n", _ES16(h->e_shnum));
	fprintf(fp, " SH String Table Index  %04d\n", _ES16(h->e_shstrndx));
}

void _print_elf32_shdr_header(FILE *fp)
{
	fprintf(fp, "[*] ELF32 Section Headers:\n");
	fprintf(fp, " Idx Name             Type          Flags Address Offset Size  ES Align LK\n");
}

void _print_elf32_shdr(FILE *fp, Elf32_Shdr *h, u32 idx, s8 *shstrtab)
{
	const s8 *name;
	s8 flags[4];

	_get_shdr_flags(flags, _ES32(h->sh_flags));

	if (shstrtab != NULL)
		fprintf(fp, " %03d %-16.16s ", idx, (shstrtab + _ES32(h->sh_name)));
	else
		fprintf(fp, " %03d %04X (N/A)       ", idx, _ES32(h->sh_name));

	name = _get_name(_sh_types, _ES32(h->sh_type));
	if(name != NULL)
		fprintf(fp, "%-13.13s ", name);
	else
		fprintf(fp, "%08X      ", _ES32(h->sh_type));

	fprintf(fp, "%s   %05X   %05X  %05X %02X %05X %03d\n", 
		flags, _ES32(h->sh_addr), _ES32(h->sh_offset), _ES32(h->sh_size), _ES32(h->sh_entsize), _ES32(h->sh_addralign), _ES32(h->sh_link));
}

void _print_elf64_shdr_header(FILE *fp)
{
	fprintf(fp, "[*] ELF64 Section Headers:\n");
	fprintf(fp, " Idx Name             Type          Flags Address            Offset   Size     ES   Align    LK\n");
}

void _print_elf64_shdr(FILE *fp, Elf64_Shdr *h, u32 idx, s8 *shstrtab)
{
	const s8 *name;
	s8 flags[4];

	_get_shdr_flags(flags, _ES64(h->sh_flags));

	if (shstrtab != NULL)
		fprintf(fp, " %03d %-16.16s ", idx, (shstrtab + _ES32(h->sh_name)));
	else
		fprintf(fp, " %03d %04X (N/A)       ", idx, _ES32(h->sh_name));

	name = _get_name(_sh_types, _ES32(h->sh_type));
	if(name != NULL)
		fprintf(fp, "%-13.13s ", name);
	else
		fprintf(fp, "%08X      ", _ES32(h->sh_type));

	fprintf(fp, "%s   %016llX   %08X %08X %04X %08X %03d\n", 
		flags, (u64)_ES64(h->sh_addr), (u32)_ES64(h->sh_offset), (u32)_ES64(h->sh_size), (u32)_ES64(h->sh_entsize), (u32)_ES64(h->sh_addralign), _ES32(h->sh_link));
}

void _print_elf32_phdr_header(FILE *fp)
{
	fprintf(fp, "[*] ELF32 Program Headers:\n");
	fprintf(fp, " Idx Type     Offset VAddr PAddr FileSize MemSize Flags Align\n");
}

void _print_elf32_phdr(FILE *fp, Elf32_Phdr *h, u32 idx)
{
	const s8 *name;

	s8 flags[4];

	_get_phdr_flags(flags, _ES32(h->p_flags));

	fprintf(fp, " %03d ", idx);

	name = _get_name(_ph_types, _ES32(h->p_type));
	if(name != NULL)
		fprintf(fp, "%-7s  ", name);
	else
		fprintf(fp, "0x%08X ", _ES32(h->p_type));

	fprintf(fp, "%05X  %05X %05X %05X    %05X   %s   %05X\n",
		_ES32(h->p_offset), _ES32(h->p_vaddr), _ES32(h->p_paddr), _ES32(h->p_filesz), _ES32(h->p_memsz), flags, _ES32(h->p_align));
}

void _print_elf64_phdr_header(FILE *fp)
{
	fprintf(fp, "[*] ELF64 Program Headers:\n");
	fprintf(fp, " Idx Type     Offset   VAddr            PAddr            FileSize MemSize  PPU SPU RSX Align\n");
}

void _print_elf64_phdr(FILE *fp, Elf64_Phdr *h, u32 idx)
{
	const s8 *name;

	s8 ppu[4], spu[4], rsx[4];

	_get_phdr_flags(ppu, _ES32(h->p_flags));
	_get_phdr_flags(spu, _ES32(h->p_flags) >> 20);
	_get_phdr_flags(rsx, _ES32(h->p_flags) >> 24);

	fprintf(fp, " %03d ", idx);

	name = _get_name(_ph_types, _ES32(h->p_type));
	if(name != NULL)
		fprintf(fp, "%-8s ", name);
	else
		fprintf(fp, "%08X ", _ES32(h->p_type));

	fprintf(fp, "%08X %016llX %016llX %08X %08X %s %s %s %08X\n", 
		(u32)_ES64(h->p_offset), (u64)_ES64(h->p_vaddr), (u64)_ES64(h->p_paddr), (u32)_ES64(h->p_filesz), (u32)_ES64(h->p_memsz), ppu, spu, rsx, (u32)_ES64(h->p_align));
}

bool self_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt)
{
	u32 i, program_type;
	const u8 *eident;
	s8 *shstrtab = NULL;
	s64 compress_difference = -1;

	//Check for SELF.
	if(_ES16(ctxt->cfh->category) != CF_CATEGORY_SELF)
		return FALSE;

	//Print SELF infos.
	_print_signed_elf_header(fp, ctxt->self.selfh);
	_print_program_identification_header(fp, ctxt->self.ai);

	program_type = _ES32(ctxt->self.ai->program_type);
	eident = ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset);

	//SPU is 32 bit.
	if(program_type == PROGRAM_TYPE_LDR || program_type == PROGRAM_TYPE_ISO || eident[EI_CLASS] == ELFCLASS32)
	{
		//32 bit ELF.
		Elf32_Ehdr *eh = (Elf32_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));

		//Print ELF header.
		_print_elf32_ehdr(fp, eh);

		Elf32_Phdr *ph = (Elf32_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));

		//Print ELF program headers.
		_print_elf32_phdr_header(fp);
		for(i = 0; i < _ES16(eh->e_phnum); i++)
			_print_elf32_phdr(fp, &ph[i], i);

		if(_ES16(eh->e_shnum) > 0)
		{
			Elf32_Shdr *sh = (Elf32_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			compress_difference = _get_compressed_self_diff(ctxt);

			if (compress_difference != -1)
			{
				u64 shstrtab_off = _ES64(ctxt->cfh->file_offset) + _ES32(sh[_ES16(eh->e_shstrndx)].sh_offset) - compress_difference;

				if (_is_shstrtab_valid((u8 *)(ctxt->scebuffer + shstrtab_off), _ES32(sh[_ES16(eh->e_shstrndx)].sh_name)))
					shstrtab = (s8 *)(ctxt->scebuffer + shstrtab_off);
			}

			//Print ELF section headers.
			_print_elf32_shdr_header(fp);
			for(i = 0; i < _ES16(eh->e_shnum); i++)
				_print_elf32_shdr(fp, &sh[i], i, shstrtab);
		}

		//Print segment ext header.
		if (_ES64(ctxt->self.selfh->version) == SELF_VERSION_3)
			_print_segment_ext_header_v3_entry_names(fp);
		else
			_print_segment_ext_header_v2_entry_names(fp);

		for(i = 0; i < _ES16(eh->e_phnum); i++)
		{
			if (_ES64(ctxt->self.selfh->version) == SELF_VERSION_3)
				_print_segment_ext_header_v3_info(fp, &ctxt->self.si[i], i);
			else
				_print_segment_ext_header_v2_info(fp, &ctxt->self.si[i], i);
		}
	}
	else
	{
		//64 bit ELF.
		Elf64_Ehdr *eh = (Elf64_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));

		//Print ELF header.
		_print_elf64_ehdr(stdout, eh);

		Elf64_Phdr *ph = (Elf64_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));

		//Print ELF program headers.
		_print_elf64_phdr_header(fp);

		for(i = 0; i < _ES16(eh->e_phnum); i++)
			_print_elf64_phdr(fp, &ph[i], i);

		if(_ES16(eh->e_shnum) > 0)
		{
			Elf64_Shdr *sh = (Elf64_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			compress_difference = _get_compressed_self_diff(ctxt);

			if (compress_difference != -1)
			{
				u64 shstrtab_off = _ES64(ctxt->cfh->file_offset) + _ES64(sh[_ES16(eh->e_shstrndx)].sh_offset) - compress_difference;
				fprintf(stdout, " Shstrtab_off            0x%016llX\n", shstrtab_off);
				
				//shstrtab_off = 0x5E03BB;
				if (_is_shstrtab_valid((u8 *)(ctxt->scebuffer + shstrtab_off), _ES32(sh[_ES16(eh->e_shstrndx)].sh_name)))
					shstrtab = (s8 *)(ctxt->scebuffer + shstrtab_off);
			}

			//Print  ELF section headers.
			_print_elf64_shdr_header(fp);
			for(i = 0; i < _ES16(eh->e_shnum); i++)
				_print_elf64_shdr(fp, &sh[i], i, shstrtab);
		}

		//Print segment extended header.
		if(ctxt->self.si != NULL)
		{
			if (_ES64(ctxt->self.selfh->version) == SELF_VERSION_3)
				_print_segment_ext_header_v3_entry_names(fp);
			else
				_print_segment_ext_header_v2_entry_names(fp);
			
			for(i = 0; i < _ES16(eh->e_phnum); i++)
			{
				if (_ES64(ctxt->self.selfh->version) == SELF_VERSION_3)
					_print_segment_ext_header_v3_info(fp, &ctxt->self.si[i], i);
				else
					_print_segment_ext_header_v2_info(fp, &ctxt->self.si[i], i);
			}
		}
	}

	//Print section extented header.
	if(ctxt->self.sv != NULL)
		_print_section_ext_header(fp, ctxt->self.sv);

	//Print supplemental headers.
	if(ctxt->self.cis != NULL)
		LIST_FOREACH(iter, ctxt->self.cis)
			_print_supplemental_header(fp, (supplemental_header_t *)iter->value);

	return TRUE;
}

bool self_print_optional_info(FILE *fp, sce_buffer_ctxt_t *ctxt)
{
	//Print optional headers.
	if(ctxt->mdec == TRUE)
		if (_ES64(ctxt->metah->opt_header_size) > 0)
		{
			LIST_FOREACH(iter, ctxt->self.ohs)
				_print_opt_header(fp, (opt_header_t *)iter->value);
		}
	return TRUE;
}

//TODO: maybe implement better.
bool self_write_to_elf(sce_buffer_ctxt_t *ctxt, const s8 *elf_out)
{
	FILE *fp;
	u32 i, program_type;
	const u8 *eident;
	u64 bytes_to_write = 0;
	s64 compress_difference = -1;

	//Check for SELF.
	if(_ES16(ctxt->cfh->category) != CF_CATEGORY_SELF)
		return FALSE;

	if((fp = fopen(elf_out, "wb")) == NULL)
		return FALSE;

	program_type = _ES32(ctxt->self.ai->program_type);
	eident = ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset);

	//SPU is 32 bit.
	if(program_type == PROGRAM_TYPE_LDR || program_type == PROGRAM_TYPE_ISO || eident[EI_CLASS] == ELFCLASS32)
	{
		//Dump individual seed.
		if(program_type == PROGRAM_TYPE_ISO)
		{
			LIST_FOREACH(iter, ctxt->self.ohs)
			{
				opt_header_t *oh = (opt_header_t *)iter->value;
				if (_ES32(oh->type) == OPT_HEADER_TYPE_INDIV_SEED)
				{
					s8 ifile[256];
					sprintf(ifile, "%s.indiv_seed.bin", elf_out);
					FILE *ifp = fopen(ifile, "wb");
					fwrite(((u8 *)oh) + sizeof(opt_header_t), sizeof(u8), _ES32(oh->size) - sizeof(opt_header_t), ifp);
					printf("[*] SEED dumped to %s.\n", ifile);
				}
			}
		}

		//32 bit ELF.
		Elf32_Ehdr ceh, *eh = (Elf32_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));
		_copy_es_elf32_ehdr(&ceh, eh);

		//Write ELF header.
		fwrite(eh, sizeof(Elf32_Ehdr), 1, fp);

		//Write program headers.
		Elf32_Phdr *ph = (Elf32_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));
		fwrite(ph, sizeof(Elf32_Phdr), ceh.e_phnum, fp);

		//Write program data.
		segment_certification_header_t *msh = ctxt->metash;
		for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
		{
			if(_ES32(msh[i].segment_type) == METADATA_SECTION_TYPE_PHDR)
			{	
				if(_ES32(msh[i].comp_algorithm) == COMP_ALGORITHM_ZLIB)
				{
					u8 *data = (u8 *)malloc(_ES32(ph[_ES32(msh[i].segment_id)].p_filesz));

					_zlib_inflate(ctxt->scebuffer + _ES64(msh[i].data_offset), _ES64(msh[i].data_size), data, _ES32(ph[_ES32(msh[i].segment_id)].p_filesz));
					fseek(fp, _ES32(ph[_ES32(msh[i].segment_id)].p_offset), SEEK_SET);
					fwrite(data, sizeof(u8), _ES32(ph[_ES32(msh[i].segment_id)].p_filesz), fp);
					free(data);
				}
				else
				{
					fseek(fp, _ES32(ph[_ES32(msh[i].segment_id)].p_offset), SEEK_SET);
					fwrite(ctxt->scebuffer + _ES64(msh[i].data_offset), sizeof(u8), (size_t)(_ES64(msh[i].data_size)), fp);
				}
			}
		}

		//Write debug sections.
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf32_Shdr *sh = (Elf32_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			compress_difference = _get_compressed_self_diff(ctxt);
			
			if (compress_difference != -1)
			{
				u64 shstrtab_off = _ES64(ctxt->cfh->file_offset) + _ES32(sh[_ES16(eh->e_shstrndx)].sh_offset) - compress_difference;

				if (_is_shstrtab_valid((u8 *)(ctxt->scebuffer + shstrtab_off), _ES32(sh[_ES16(eh->e_shstrndx)].sh_name)))
				{
					bytes_to_write = ((_ES64(ctxt->cfh->file_size)) - ftell(fp));
					fwrite((ctxt->scebuffer + (_ES64(ctxt->cfh->file_size) + _ES64(ctxt->cfh->file_offset)- compress_difference - bytes_to_write)), sizeof(u8), (size_t)(bytes_to_write), fp);
				}
			}
		}

		//Write section headers.
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf32_Shdr *sh = (Elf32_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			fseek(fp, ceh.e_shoff, SEEK_SET);
			fwrite(sh, sizeof(Elf32_Shdr), ceh.e_shnum, fp);
		}
	}
	else
	{
		//64 bit ELF.
		Elf64_Ehdr ceh, *eh = (Elf64_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));
		_copy_es_elf64_ehdr(&ceh, eh);

		//Write ELF header.
		fwrite(eh, sizeof(Elf64_Ehdr), 1, fp);

		//Write program headers.
		Elf64_Phdr *ph = (Elf64_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));
		fwrite(ph, sizeof(Elf64_Phdr), ceh.e_phnum, fp);

		//Write program data.
		segment_certification_header_t *msh = ctxt->metash;

		for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
		{
			if(_ES32(msh[i].segment_type) == METADATA_SECTION_TYPE_PHDR)
			{
				if(_ES32(msh[i].comp_algorithm) == COMP_ALGORITHM_ZLIB)
				{
					u8 *data = (u8 *)malloc((size_t)_ES64(ph[_ES32(msh[i].segment_id)].p_filesz));

					_zlib_inflate(ctxt->scebuffer + _ES64(msh[i].data_offset), _ES64(msh[i].data_size), data, _ES64(ph[_ES32(msh[i].segment_id)].p_filesz));
					fseek(fp, (long)_ES64(ph[_ES32(msh[i].segment_id)].p_offset), SEEK_SET);
					fwrite(data, sizeof(u8), (size_t)_ES64(ph[_ES32(msh[i].segment_id)].p_filesz), fp);
					free(data);
				}
				else
				{
					fseek(fp, (long)_ES64(ph[_ES32(msh[i].segment_id)].p_offset), SEEK_SET);
					fwrite(ctxt->scebuffer + _ES64(msh[i].data_offset), sizeof(u8), (size_t)(_ES64(msh[i].data_size)), fp);
				}
			}
		}

		//Write debug sections
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf64_Shdr *sh = (Elf64_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			compress_difference = _get_compressed_self_diff(ctxt);

			if (compress_difference != -1)
			{				
				u64 shstrtab_off = _ES64(ctxt->cfh->file_offset) + _ES64(sh[_ES16(eh->e_shstrndx)].sh_offset) - compress_difference;

				if (_is_shstrtab_valid((u8 *)(ctxt->scebuffer + shstrtab_off), _ES32(sh[_ES16(eh->e_shstrndx)].sh_name)))
				{
					bytes_to_write = ((_ES64(ctxt->cfh->file_size)) - ftell(fp));
					fwrite((ctxt->scebuffer + (_ES64(ctxt->cfh->file_size) + _ES64(ctxt->cfh->file_offset) - compress_difference - bytes_to_write)), sizeof(u8), (size_t)(bytes_to_write), fp);
				}
			}
		}

		//Write section headers.
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf64_Shdr *sh = (Elf64_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			fseek(fp, (long)(ceh.e_shoff), SEEK_SET);
			fwrite(sh, sizeof(Elf64_Shdr), ceh.e_shnum, fp);
		}
	}

	fclose(fp);

	return TRUE;
}



bool fself_write_to_elf(sce_buffer_ctxt_t *ctxt, const s8 *elf_out)
{
	FILE *fp;
	u32 i, program_type;
	const u8 *eident;
	u64 bytes_to_write = 0;
	s64 compress_difference = -1;

	//Check for SELF.
	if(_ES16(ctxt->cfh->category) != CF_CATEGORY_SELF)
		return FALSE;

	if((fp = fopen(elf_out, "wb")) == NULL)
		return FALSE;

	program_type = _ES32(ctxt->self.ai->program_type);
	eident = ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset);

	//SPU is 32 bit.
	if(program_type == PROGRAM_TYPE_LDR || program_type == PROGRAM_TYPE_ISO || eident[EI_CLASS] == ELFCLASS32)
	{

		//32 bit ELF.
		Elf32_Ehdr ceh, *eh = (Elf32_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));
		_copy_es_elf32_ehdr(&ceh, eh);

		//Write ELF header.
		fwrite(eh, sizeof(Elf32_Ehdr), 1, fp);

		//Write program headers.
		Elf32_Phdr *ph = (Elf32_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));
		fwrite(ph, sizeof(Elf32_Phdr), ceh.e_phnum, fp);

		//Write program data.
		fprintf(stdout, "[*] Write segments.\n");
		segment_ext_header_t *seh = ctxt->self.si;

		for(i = 0; i < ceh.e_phnum; i++)
		{
			//Handling LOADable program segments only.
			if(_ES32(ph[i].p_type) == PT_LOAD)
			{
				if(_ES32(seh[i].comp_algorithm) == COMP_ALGORITHM_ZLIB)
				{
					u8 *data = (u8 *)malloc(_ES32(ph[i].p_filesz));

					_zlib_inflate(ctxt->scebuffer + _ES64(seh[i].offset), _ES64(seh[i].size), data, _ES32(ph[i].p_filesz));
					fseek(fp, _ES32(ph[i].p_offset), SEEK_SET);
					fwrite(data, sizeof(u8), (size_t)_ES32(ph[i].p_filesz), fp);
					free(data);
				}
				else
				{
					fseek(fp, _ES32(ph[i].p_offset), SEEK_SET);
					fwrite(ctxt->scebuffer + _ES64(seh[i].offset), sizeof(u8), (size_t)(_ES64(seh[i].size)), fp);
				}
			}
		}

		fprintf(stdout, "[*] Write sections.\n");

		//Write debug sections
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf32_Shdr *sh = (Elf32_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			compress_difference = _get_compressed_self_diff(ctxt);
			
			if (compress_difference != -1)
			{
				u64 shstrtab_off = _ES64(ctxt->cfh->file_offset) + _ES32(sh[_ES16(eh->e_shstrndx)].sh_offset) - compress_difference;

				if (_is_shstrtab_valid((u8 *)(ctxt->scebuffer + shstrtab_off), _ES32(sh[_ES16(eh->e_shstrndx)].sh_name)))
				{
					bytes_to_write = ((_ES64(ctxt->cfh->file_size)) - ftell(fp));
					fwrite((ctxt->scebuffer + (_ES64(ctxt->cfh->file_size) + _ES64(ctxt->cfh->file_offset)- compress_difference - bytes_to_write)), sizeof(u8), (size_t)(bytes_to_write), fp);
				}
			}
		}

		//Write section headers.
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf32_Shdr *sh = (Elf32_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			fseek(fp, ceh.e_shoff, SEEK_SET);
			fwrite(sh, sizeof(Elf32_Shdr), ceh.e_shnum, fp);
		}

	}
	else
	{
		//64 bit ELF.
		Elf64_Ehdr ceh, *eh = (Elf64_Ehdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->elf_header_offset));
		_copy_es_elf64_ehdr(&ceh, eh);

		//Write ELF header.
		fwrite(eh, sizeof(Elf64_Ehdr), 1, fp);

		//Write program headers.
		Elf64_Phdr *ph = (Elf64_Phdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->phdr_offset));
		fwrite(ph, sizeof(Elf64_Phdr), ceh.e_phnum, fp);

		//Write program data.
		fprintf(stdout, "[*] Write segments.\n");
		segment_ext_header_t *seh = ctxt->self.si;

		for(i = 0; i < ceh.e_phnum; i++)
		{
			//Handling LOADable program segments only.
			if(_ES32(ph[i].p_type) == PT_LOAD)
			{
				if(_ES32(seh[i].comp_algorithm) == COMP_ALGORITHM_ZLIB)
				{
					u8 *data = (u8 *)malloc((size_t)_ES64(ph[i].p_filesz));

					_zlib_inflate(ctxt->scebuffer + _ES64(seh[i].offset), _ES64(seh[i].size), data, _ES64(ph[i].p_filesz));
					fseek(fp, (long)_ES64(ph[i].p_offset), SEEK_SET);
					fwrite(data, sizeof(u8), (size_t)_ES64(ph[i].p_filesz), fp);
					free(data);
				}
				else
				{
					fseek(fp, (long)_ES64(ph[i].p_offset), SEEK_SET);
					fwrite(ctxt->scebuffer + _ES64(seh[i].offset), sizeof(u8), (size_t)(_ES64(seh[i].size)), fp);
				}
			}
		}

		fprintf(stdout, "[*] Write sections.\n");

		//Write debug sections.
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf64_Shdr *sh = (Elf64_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			compress_difference = _get_compressed_self_diff(ctxt);

			if (compress_difference != -1)
			{				
				u64 shstrtab_off = _ES64(ctxt->cfh->file_offset) + _ES64(sh[_ES16(eh->e_shstrndx)].sh_offset) - compress_difference;

				if (_is_shstrtab_valid((u8 *)(ctxt->scebuffer + shstrtab_off), _ES32(sh[_ES16(eh->e_shstrndx)].sh_name)))
				{
					bytes_to_write = ((_ES64(ctxt->cfh->file_size)) - ftell(fp));
					fwrite((ctxt->scebuffer + (_ES64(ctxt->cfh->file_size) + _ES64(ctxt->cfh->file_offset) - compress_difference - bytes_to_write)), sizeof(u8), (size_t)(bytes_to_write), fp);
				}
			}
		}

		//Write section headers.
		if(_ES64(ctxt->self.selfh->shdr_offset) != 0)
		{
			Elf64_Shdr *sh = (Elf64_Shdr *)(ctxt->scebuffer + _ES64(ctxt->self.selfh->shdr_offset));
			fseek(fp, (long)(ceh.e_shoff), SEEK_SET);
			fwrite(sh, sizeof(Elf64_Shdr), ceh.e_shnum, fp);
		}
	}

	fclose(fp);

	return TRUE;

}

/*! Static zero control flags. */
static u8 _static_control_flags[0x20] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*! Static control digest1. */
static u8 _static_control_digest[0x14] = 
{
	0x62, 0x7C, 0xB1, 0x80, 0x8A, 0xB9, 0x38, 0xE3, 0x2C, 0x8C, 0x09, 0x17, 0x08, 0x72, 0x6A, 0x57, 0x9E, 0x25, 0x86, 0xE4
};

static bool _create_control_infos(sce_buffer_ctxt_t *ctxt, self_config_t *sconf)
{
	supplemental_header_t *ci;
	u32 program_type = _ES32(ctxt->self.ai->program_type);
	u32 media_binding_flags = 0x20000; // flash type by default

	//Step 1.
	switch(program_type)
	{
	case PROGRAM_TYPE_LV0:
	case PROGRAM_TYPE_LV1:
	case PROGRAM_TYPE_LV2:
	case PROGRAM_TYPE_APP:
	case PROGRAM_TYPE_ISO:
	case PROGRAM_TYPE_LDR:
	case PROGRAM_TYPE_NPDRM: //TODO: <-- figure more out.
		{
			//Add control flags.
			ci = (supplemental_header_t *)malloc(sizeof(supplemental_header_t) + sizeof(ci_data_flags_t));
			ci->type = _ES32(SPPL_HEADER_TYPE_SELF_CONTROL_FLAGS);
			ci->size = _ES32(sizeof(supplemental_header_t) + sizeof(ci_data_flags_t));
			ci->next = _ES64(1);

			ci_data_flags_t *cif = (ci_data_flags_t *)((u8 *)ci + sizeof(supplemental_header_t));

			//Add default flags.
			if(sconf->ctrl_flags == NULL)
				memcpy(cif->data, _static_control_flags, 0x20);
			else
				memcpy(cif->data, sconf->ctrl_flags, 0x20);

			list_add_back(ctxt->self.cis, ci);
		}
		break;
	}

	//Step 2.
	switch(program_type)
	{
	case PROGRAM_TYPE_LV0:
	case PROGRAM_TYPE_LV1:
	case PROGRAM_TYPE_LV2:
	case PROGRAM_TYPE_APP:
	case PROGRAM_TYPE_ISO:
	case PROGRAM_TYPE_LDR:
	case PROGRAM_TYPE_NPDRM:
		{
			//Add elf digest header.
			ci = (supplemental_header_t *)malloc(sizeof(supplemental_header_t) + sizeof(ci_data_digest_40_t));
			ci->type = _ES32(SPPL_HEADER_TYPE_ELF_DIGEST_HEADER);
			ci->size = _ES32(sizeof(supplemental_header_t) + sizeof(ci_data_digest_40_t));
			if(program_type == PROGRAM_TYPE_NPDRM)
				ci->next = _ES64(1);
			else
				ci->next = _ES64(0);

			ci_data_digest_40_t *cid = (ci_data_digest_40_t *)((u8 *)ci + sizeof(supplemental_header_t));
			memcpy(cid->digest1, _static_control_digest, 0x14);
			memset(cid->digest2, 0, 0x14);
			sha1(ctxt->makeself->elf, ctxt->makeself->elf_len, cid->digest2);

			//TODO: check that. 
			if (sconf->cap_flags != NULL)
				media_binding_flags = _ES32((*(u32 *)(sconf->cap_flags+0x1C)));

			if((program_type == PROGRAM_TYPE_NPDRM) || ((media_binding_flags & 0x40000) != 0))
			{
				cid->fw_version = sce_hexver_to_decver(sconf->fw_version);
			}
			else
				cid->fw_version = 0;

			//Fixup.
			_es_ci_data_digest_40(cid);
			
			list_add_back(ctxt->self.cis, ci);
		}
		break;
	}

	//Step 3.
	switch(program_type)
	{
	case PROGRAM_TYPE_NPDRM:
		{
			//Add NPDRM header.
			if(sconf->npdrm_config == NULL)
				return FALSE;

			ci = (supplemental_header_t *)malloc(sizeof(supplemental_header_t) + sizeof(ci_data_npdrm_t));
			ci->type = _ES32(SPPL_HEADER_TYPE_NPDRM_HEADER);
			ci->size = _ES32(sizeof(supplemental_header_t) + sizeof(ci_data_npdrm_t));
			ci->next = _ES64(0);

			ci_data_npdrm_t *cinp = (ci_data_npdrm_t *)((u8 *)ci + sizeof(supplemental_header_t));

			//Create NPDRM control info.
			if(np_create_ci(sconf->npdrm_config, cinp) == FALSE)
			{
				free(ci);
				return FALSE;
			}

			list_add_back(ctxt->self.cis, ci);
		}
		break;
	}

	return TRUE;
}

static void _set_cap_flags(u32 program_type, oh_data_cap_flags_t *capf)
{
	switch(program_type)
	{
	case PROGRAM_TYPE_LV0:
		capf->flags = CAP_FLAG_ARCADE | CAP_FLAG_CEX | CAP_FLAG_DEX | CAP_FLAG_DEH | 0x3; //0x7B;
		capf->unk6 = 1;
		break;
	case PROGRAM_TYPE_LV1:
		capf->flags = CAP_FLAG_ARCADE | CAP_FLAG_CEX | CAP_FLAG_DEX | CAP_FLAG_DEH | 0x3; //0x7B;
		capf->unk6 = 1;
		break;
	case PROGRAM_TYPE_LV2:
		capf->flags = CAP_FLAG_ARCADE | CAP_FLAG_CEX | CAP_FLAG_DEX | CAP_FLAG_DEH | 0x3; //0x7B;
		capf->unk6 = 1;
		break;
	case PROGRAM_TYPE_APP:
		capf->flags = CAP_FLAG_ARCADE | CAP_FLAG_CEX | CAP_FLAG_DEX | CAP_FLAG_DEH | 0x3; //0x7B;
		capf->unk6 = 1;
		capf->unk7 = 0x20000;
		break;
	case PROGRAM_TYPE_ISO:
		capf->flags = CAP_FLAG_ARCADE | CAP_FLAG_CEX | CAP_FLAG_DEX | CAP_FLAG_DEH; //0x78;
		break;
	case PROGRAM_TYPE_LDR:
		capf->flags = CAP_FLAG_ARCADE | CAP_FLAG_CEX | CAP_FLAG_DEX | CAP_FLAG_DEH; //0x78;
		break;
	case PROGRAM_TYPE_NPDRM:
		capf->flags = CAP_FLAG_CEX | CAP_FLAG_DEX | CAP_FLAG_DEH | 0x3; //0x3B;
		capf->unk6 = 1;
		capf->unk7 = 0x2000;
		break;
	}

	_es_oh_data_cap_flags(capf);
}

static bool _create_optional_headers(sce_buffer_ctxt_t *ctxt, self_config_t *sconf)
{
	opt_header_t *oh;
	u32 program_type = _ES32(ctxt->self.ai->program_type);

	//Step 1.
	switch(program_type)
	{
	case PROGRAM_TYPE_LV0:
	case PROGRAM_TYPE_LV1:
	case PROGRAM_TYPE_LV2:
	case PROGRAM_TYPE_APP:
	case PROGRAM_TYPE_ISO:
	case PROGRAM_TYPE_LDR:
	case PROGRAM_TYPE_NPDRM:
		{
			//Add capability flags.
			oh = (opt_header_t *)malloc(sizeof(opt_header_t) + sizeof(oh_data_cap_flags_t));
			oh->type = _ES32(OPT_HEADER_TYPE_CAP_FLAGS);
			oh->size = _ES32(sizeof(opt_header_t) + sizeof(oh_data_cap_flags_t));
			if(program_type == PROGRAM_TYPE_ISO)
				oh->next = _ES64(1);
			else
				oh->next = _ES64(0);

			oh_data_cap_flags_t *capf = (oh_data_cap_flags_t *)((u8 *)oh + sizeof(opt_header_t));
			memset(capf, 0, 0x20);

			//Add default flags.
			if(sconf->cap_flags == NULL)
				_set_cap_flags(program_type, capf);
			else
				memcpy(capf, sconf->cap_flags, 0x20);

			list_add_back(ctxt->self.ohs, oh);
		}
		break;
	}

	//Step 2.
	switch(program_type)
	{
	case PROGRAM_TYPE_ISO:
		{
			//Add individual seed.
			oh = (opt_header_t *)malloc(sizeof(opt_header_t) + 0x100);
			oh->type = _ES32(OPT_HEADER_TYPE_INDIV_SEED);
			oh->size = _ES32(sizeof(opt_header_t) + 0x100);
			oh->next = _ES64(0);

			u8 *is = (u8 *)oh + sizeof(opt_header_t);
			memset(is, 0, 0x100);
			if(sconf->indiv_seed != NULL)
				memcpy(is, sconf->indiv_seed, sconf->indiv_seed_size);

			list_add_back(ctxt->self.ohs, oh);
		}
		break;
	}

	return TRUE;
}

static void _fill_sce_version(sce_buffer_ctxt_t *ctxt)
{
	ctxt->self.sv->header_type = _ES32(SECTION_EXT_HEADER_TYPE_SCEVERSION);
	ctxt->self.sv->present = _ES32(SCE_VERSION_NOT_PRESENT);
	ctxt->self.sv->size = _ES32(sizeof(section_ext_header_t));
	ctxt->self.sv->unknown_3 = _ES32(0x00000000);
}

static void _add_phdr_section(sce_buffer_ctxt_t *ctxt, u32 p_type, u32 size, u32 idx)
{
	//Offset gets set later.
	ctxt->self.si[idx].offset = 0;
	ctxt->self.si[idx].size = size;

	if(p_type == PT_LOAD || p_type == PT_SCE_PPURELA || p_type == PT_SCE_SEGSYM)
		ctxt->self.si[idx].encrypted = 1; //Encrypted LOAD (?).
	else
		ctxt->self.si[idx].encrypted = 0; //No LOAD (?).

	ctxt->self.si[idx].comp_algorithm = COMP_ALGORITHM_PLAIN;
	ctxt->self.si[idx].unknown_0 = 0; //Unknown.
	ctxt->self.si[idx].unknown_1 = 0; //Unknown.
}

static bool _add_shdrs_section(sce_buffer_ctxt_t *ctxt, u32 idx)
{
	//Add a segment for the section headers.
	if(ctxt->makeself->shdrs != NULL)
	{
		u32 shsize = ctxt->makeself->shsize;
		void *sec = _memdup(ctxt->makeself->shdrs, shsize);
		sce_add_data_section(ctxt, sec, shsize, FALSE);

		//Fill segment certification header.
		sce_set_segment_certification_header(ctxt, METADATA_SECTION_TYPE_SHDR, FALSE, idx);

		return TRUE;
	}

	return FALSE;
}

static bool _build_self_32(sce_buffer_ctxt_t *ctxt, self_config_t *sconf)
{
	u32 i;

	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdrs;
	//Elf32_Shdr *shdrs;

	//Copy ELF header.
	ctxt->makeself->ehdr = (Elf32_Ehdr *)_memdup(ctxt->makeself->elf, sizeof(Elf32_Ehdr));
	ctxt->makeself->ehsize = sizeof(Elf32_Ehdr);
	ehdr = (Elf32_Ehdr *)_memdup(ctxt->makeself->elf, sizeof(Elf32_Ehdr));
	_es_elf32_ehdr(ehdr);

	//Copy program headers.
	ctxt->makeself->phdrs = (Elf32_Phdr *)_memdup(ctxt->makeself->elf + ehdr->e_phoff, sizeof(Elf32_Phdr) * ehdr->e_phnum);
	ctxt->makeself->phsize = sizeof(Elf32_Phdr) * ehdr->e_phnum;
	phdrs = (Elf32_Phdr *)_memdup(ctxt->makeself->elf + ehdr->e_phoff, sizeof(Elf32_Phdr) * ehdr->e_phnum);

	//Copy section headers.
	if(ehdr->e_shnum != 0)
	{
		ctxt->makeself->shdrs = (Elf32_Shdr *)_memdup(ctxt->makeself->elf + ehdr->e_shoff, sizeof(Elf32_Shdr) * ehdr->e_shnum);
		ctxt->makeself->shsize = sizeof(Elf32_Shdr) * ehdr->e_shnum;
		//shdrs = (Elf32_Shdr *)_memdup(ctxt->makeself->elf + ehdr->e_shoff, sizeof(Elf32_Shdr) * ehdr->e_shnum);
	}

	//Allocate metadata section headers (one for each program header and one for the section headers).
	ctxt->metash = (segment_certification_header_t *)malloc(sizeof(segment_certification_header_t) * (ehdr->e_phnum + 1));

	//Copy segments, fill segment infos and metadata section headers.
	ctxt->self.si = (segment_ext_header_t *)malloc(sizeof(segment_ext_header_t) * ehdr->e_phnum);
	u32 loff = 0xFFFFFFFF, skip = 0;
	for(i = 0; i < ehdr->e_phnum; i++)
	{
		_es_elf32_phdr(&phdrs[i]);

		//Add section info.
		_add_phdr_section(ctxt, phdrs[i].p_type, phdrs[i].p_filesz, i);

		//Fill metadata section header but skip identical program header offsets.
		if(sconf->skip_sections == TRUE && (phdrs[i].p_offset == loff || !(phdrs[i].p_type == PT_LOAD || phdrs[i].p_type == PT_SCE_PPURELA || phdrs[i].p_type == PT_SCE_SEGSYM)))
		{
			const s8 *name = _get_name(_ph_types, phdrs[i].p_type);
			if(name != NULL)
				_LOG_VERBOSE("Skipped program header %-8s @ 0x%08X (0x%08X)\n", name, phdrs[i].p_offset, phdrs[i].p_filesz);
			else
				_LOG_VERBOSE("Skipped program header 0x%08X @ 0x%08X (0x%08X)\n", phdrs[i].p_type, phdrs[i].p_offset, phdrs[i].p_filesz);
			skip++;
		}
		else
		{
			void *sec = _memdup(ctxt->makeself->elf + phdrs[i].p_offset, phdrs[i].p_filesz);
			//SPU sections may be compressed.
			sce_add_data_section(ctxt, sec, phdrs[i].p_filesz, TRUE);
			sce_set_segment_certification_header(ctxt, METADATA_SECTION_TYPE_PHDR, TRUE /*(phdrs[i].p_type == PT_LOAD || phdrs[i].p_type == PT_SCE_PPURELA || phdrs[i].p_type == PT_SCE_SEGSYM) ? TRUE : FALSE*/, i - skip);
		}

		loff = phdrs[i].p_offset;
	}

	//Segment info count.
	ctxt->makeself->si_cnt = ehdr->e_phnum;
	//Number of segment infos that are present as data sections.
	ctxt->makeself->si_sec_cnt = ehdr->e_phnum;

	//Add a section for the section headers.
	if(sconf->add_shdrs == TRUE)
		if(_add_shdrs_section(ctxt, i - skip) == TRUE)
			i++;

	//Metadata.
	i -= skip;
	ctxt->metah->section_count = _ES32(i);

	return TRUE;
}

static bool _build_self_64(sce_buffer_ctxt_t *ctxt, self_config_t *sconf)
{
	u32 i;

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdrs;
	//Elf64_Shdr *shdrs;

	//Copy ELF header.
	ctxt->makeself->ehdr = (Elf64_Ehdr *)_memdup(ctxt->makeself->elf, sizeof(Elf64_Ehdr));
	ctxt->makeself->ehsize = sizeof(Elf64_Ehdr);
	ehdr = (Elf64_Ehdr *)_memdup(ctxt->makeself->elf, sizeof(Elf64_Ehdr));
	_es_elf64_ehdr(ehdr);

	//Copy program headers.
	ctxt->makeself->phdrs = (Elf64_Phdr *)_memdup(ctxt->makeself->elf + ehdr->e_phoff, sizeof(Elf64_Phdr) * ehdr->e_phnum);
	ctxt->makeself->phsize = sizeof(Elf64_Phdr) * ehdr->e_phnum;
	phdrs = (Elf64_Phdr *)_memdup(ctxt->makeself->elf + ehdr->e_phoff, sizeof(Elf64_Phdr) * ehdr->e_phnum);

	//Copy section headers.
	if(ehdr->e_shnum != 0)
	{
		ctxt->makeself->shdrs = (Elf64_Shdr *)_memdup(ctxt->makeself->elf + ehdr->e_shoff, sizeof(Elf64_Shdr) * ehdr->e_shnum);
		ctxt->makeself->shsize = sizeof(Elf64_Shdr) * ehdr->e_shnum;
		//shdrs = (Elf64_Shdr *)_memdup(ctxt->makeself->elf + ehdr->e_shoff, sizeof(Elf64_Shdr) * ehdr->e_shnum);
	}

	//Allocate segment certification headers (one for each program header and one for the section headers).
	ctxt->metash = (segment_certification_header_t *)malloc(sizeof(segment_certification_header_t) * (ehdr->e_phnum + 1));

	//Copy segments, fill segment ext headers and segment certification headers.
	ctxt->self.si = (segment_ext_header_t *)malloc(sizeof(segment_ext_header_t) * ehdr->e_phnum);
	u32 loff = 0xFFFFFFFF, skip = 0;
	for(i = 0; i < ehdr->e_phnum; i++)
	{
		_es_elf64_phdr(&phdrs[i]);

		//Add section info.
		_add_phdr_section(ctxt, phdrs[i].p_type, (u32)phdrs[i].p_filesz, i);

		//TODO: what if the size differs, why skip other program headers?
		//Fill metadata section header but skip identical program header offsets.
		if(sconf->skip_sections == TRUE && (phdrs[i].p_offset == loff || !(phdrs[i].p_type == PT_LOAD || phdrs[i].p_type == PT_SCE_PPURELA || phdrs[i].p_type == PT_SCE_SEGSYM)))
		{
			const s8 *name = _get_name(_ph_types, phdrs[i].p_type);
			if(name != NULL)
				_LOG_VERBOSE("Skipped program header %-8s @ 0x%016llX (0x%016llX)\n", name, phdrs[i].p_offset, phdrs[i].p_filesz);
			else
				_LOG_VERBOSE("Skipped program header 0x%08X @ 0x%016llX (0x%016llX)\n", phdrs[i].p_type, phdrs[i].p_offset, phdrs[i].p_filesz);
			skip++;
		}
		else
		{
			void *sec = _memdup(ctxt->makeself->elf + phdrs[i].p_offset, (u32)phdrs[i].p_filesz);
			//PPU sections may be compressed.
			sce_add_data_section(ctxt, sec, (u32)phdrs[i].p_filesz, TRUE);
			sce_set_segment_certification_header(ctxt, METADATA_SECTION_TYPE_PHDR, TRUE /*(phdrs[i].p_type == PT_LOAD || phdrs[i].p_type == PT_PS3_PRX_RELOC || phdrs[i].p_type == 0x700000A8) ? TRUE : FALSE*/, i - skip);
		}

		loff = (u32)phdrs[i].p_offset;
	}

	//Segment info count.
	ctxt->makeself->si_cnt = ehdr->e_phnum;
	//Number of segment infos that are present as data sections.
	ctxt->makeself->si_sec_cnt = i - skip;

	//Add a section for the section headers.
	if(sconf->add_shdrs == TRUE)
		if(_add_shdrs_section(ctxt, i - skip) == TRUE)
			i++;

	//Metadata.
	i -= skip;
	ctxt->metah->section_count = _ES32(i);

	return TRUE;
}

bool self_build_self(sce_buffer_ctxt_t *ctxt, self_config_t *sconf)
{
	const u8 *eident;

	//Fill config values.
	ctxt->cfh->attribute = _ES16(sconf->key_revision);
	ctxt->self.ai->auth_id = _ES64(sconf->auth_id);
	ctxt->self.ai->vender_id = _ES32(sconf->vender_id);
	ctxt->self.ai->program_type = _ES32(sconf->program_type);
	ctxt->self.ai->version = _ES64(sconf->app_version);

	//Create control infos.
	if(_create_control_infos(ctxt, sconf) == FALSE)
	{
		printf("[*] Error: Could not create SELF control infos.\n");
		return FALSE;
	}

	if(sconf->indiv_seed != NULL && sconf->program_type != PROGRAM_TYPE_ISO)
		printf("[*] Warning: Skipping individual seed for non-ISO SELF.\n");

	//Create optional headers.
	if(_create_optional_headers(ctxt, sconf) == FALSE)
	{
		printf("[*] Error: Could not create SELF optional headers.\n");
		return FALSE;
	}

	//Set SCE version.
	_fill_sce_version(ctxt);

	//Check for 32 bit or 64 bit ELF.
	eident = (const u8*)ctxt->makeself->elf;
	if(sconf->program_type == PROGRAM_TYPE_LDR || sconf->program_type == PROGRAM_TYPE_ISO || eident[EI_CLASS] == ELFCLASS32)
		return _build_self_32(ctxt, sconf);
	return _build_self_64(ctxt, sconf);
}
