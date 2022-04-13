/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _TABLES_H_
#define _TABLES_H_

#include "types.h"
#include "util.h"

/*! SELF types. */
extern id_to_name_t _program_types[];

/*! SELF types as parameter. */
extern id_to_name_t _program_types_params[];

/*! Supplemental header types. */
extern id_to_name_t _supplemental_header_types[];

/*! Optional header types. */
extern id_to_name_t _optional_header_types[];

/*! NPDRM types. */
extern id_to_name_t _np_drm_types[];

/*! NPDRM application types. */
extern id_to_name_t _np_app_types[];

/*! Auth IDs. */
extern id_to_name_t _auth_ids[];

/*! Vender IDs. */
extern id_to_name_t _vender_ids[];

/*! ELF machines. */
extern id_to_name_t _e_machines[];

/*! ELF types. */
extern id_to_name_t _e_types[];

/*! Section header types. */
extern id_to_name_t _sh_types[];

/*! Program header types. */
extern id_to_name_t _ph_types[];

/*! Metadata section header types. */
extern id_to_name_t _msh_types[];

/*! Key types. */
extern id_to_name_t _key_categories[];

/*! Cert file types. */
extern id_to_name_t _cert_file_categories[];

/*! Signature algorithms. */
extern id_to_name_t _sign_algorithms[];

#endif
