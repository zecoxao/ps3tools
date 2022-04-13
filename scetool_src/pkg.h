/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _PKG_H_
#define _PKG_H_

#include "types.h"
#include "sce.h"

/*! Update package header. */
typedef struct _update_package_header
{
	u32 header_version;		//0x00
	u32 type;				//0x04
	u64 id;					//0x08
	u64 data_version;		//0x10
	u64 data_size;			//0x18
	u64 comp_size;			//0x20
	u32 attribute;			//0x28
	u32 region;				//0x2C
	u64 image_offset;		//0x30
	u64 reserved_0;			//0x38
} update_package_header_t;

/*! Update package contents header. */
typedef struct _update_package_contents_header
{
	u64 header_version;		//0x00
	u64 header_size;		//0x08
	u64 chunk_offset;		//0x10
	u64 chunk_size;			//0x18
	u64 current_chunk;		//0x20
	u64 chunks_total;		//0x28
	u64 reserved_0;			//0x30
	u64 reserved_1;			//0x38
} update_package_contents_header_t;


/*! Print PKG infos. */
void pkg_print(FILE *fp, sce_buffer_ctxt_t *ctxt);

/*! Create BIN from PKG. */
bool pkg_write_to_bin(sce_buffer_ctxt_t *ctxt, const s8 *bin_out);

#endif
