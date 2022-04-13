/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>

#include "types.h"
#include "sce.h"
#include "pkg.h"
#include "util.h"

void _print_update_package_header(FILE *fp, update_package_header_t *h)
{
	fprintf(fp, "[*] Update Package Header:\n");
	fprintf(fp, " Header Version  0x%08X\n", _ES32(h->header_version));
	fprintf(fp, " Update Type     0x%08X\n", _ES32(h->type));
	fprintf(fp, " Id              0x%016llX\n", _ES64(h->id));
	fprintf(fp, " Data Version    0x%016llX\n", _ES64(h->data_version));
	fprintf(fp, " Data Size       0x%016llX\n", _ES64(h->data_size));
	fprintf(fp, " Comp Size       0x%016llX\n", _ES64(h->comp_size));
	fprintf(fp, " Attribute       0x%08X\n", _ES32(h->attribute));
	fprintf(fp, " Region          0x%08X\n", _ES32(h->region));
	fprintf(fp, " Image Offset    0x%016llX\n", _ES64(h->image_offset));
}

void _print_update_package_contents_header(FILE *fp, update_package_contents_header_t *h)
{
	fprintf(fp, "[*] Update Package Contents Header:\n");
	fprintf(fp, " Header Version  0x%016llX\n", _ES64(h->header_version));
	fprintf(fp, " Header Size     0x%016llX\n", _ES64(h->header_size));
	fprintf(fp, " Chunk Offset    0x%016llX\n", _ES64(h->chunk_offset));
	fprintf(fp, " Chunk Size      0x%016llX\n", _ES64(h->chunk_size));
	fprintf(fp, " Current Chunk   0x%016llX\n", _ES64(h->current_chunk));
	fprintf(fp, " Chunks Total    0x%016llX\n", _ES64(h->chunks_total));
}

void pkg_print(FILE *fp, sce_buffer_ctxt_t *ctxt)
{
	//Print PKG infos.
	_print_update_package_header(fp, (update_package_header_t *)(ctxt->scebuffer + _ES64(ctxt->cfh->file_offset)));
	_print_update_package_contents_header(fp, (update_package_contents_header_t *)(ctxt->scebuffer + _ES64(ctxt->cfh->file_offset) + 0x40));
}

bool pkg_write_to_bin(sce_buffer_ctxt_t *ctxt, const s8 *bin_out)
{
	FILE *fp;
	u32 i;

	//Check for PKG.
	if(_ES16(ctxt->cfh->category) != CF_CATEGORY_PKG)
		return FALSE;

	if((fp = fopen(bin_out, "wb")) == NULL)
		return FALSE;

	//Write PKG content.
	segment_certification_header_t *sch = ctxt->metash;
	update_package_header_t *pkgh = (update_package_header_t *)(ctxt->scebuffer + _ES64(ctxt->cfh->file_offset));

	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
	{
		if(_ES32(sch[i].segment_type) == 3)
		{	
			if(_ES32(sch[i].comp_algorithm) == COMP_ALGORITHM_ZLIB)
			{
				u8 *data = (u8 *)malloc((u32)(_ES64(pkgh->data_size)));

				_zlib_inflate(ctxt->scebuffer + _ES64(sch[i].data_offset), _ES64(sch[i].data_size), data, _ES64(pkgh->data_size));
				fseek(fp, 0, SEEK_SET);
				fwrite(data, sizeof(u8), ((u32)_ES64(pkgh->data_size)), fp);
				free(data);
			}
			else
			{
				fseek(fp, 0, SEEK_SET);
				fwrite(ctxt->scebuffer + _ES64(sch[i].data_offset), sizeof(u8), (size_t)(_ES64(sch[i].data_size)), fp);
			}
		}
	}

	return TRUE;
}