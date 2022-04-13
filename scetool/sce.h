/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _SCE_H_
#define _SCE_H_

#include <stdio.h>
#include <string.h>

#include "types.h"
#include "list.h"

/*! SCE file align. */
#define SCE_ALIGN 0x10
/*! Header align. */
#define HEADER_ALIGN 0x80

/*! Certified file magic value ("SCE\0"). */
#define CF_MAGIC 0x53434500

/*! Certified file versions. */
/*! Certified file version 2. */
#define CF_VERSION_2 2
/*! Certified file version 3. */
#define CF_VERSION_3 3

/*! Certified File Attributes. */
#define ATTRIBUTE_FAKE_CERTIFIED_FILE 0x8000

/*! Certified file categories. */
/*! SELF file. */
#define CF_CATEGORY_SELF 1
/*! RVK file. */
#define CF_CATEGORY_RVK 2
/*! PKG file. */
#define CF_CATEGORY_PKG 3
/*! SPP file. */
#define CF_CATEGORY_SPP 4

/*! Section ext header types. */
/*! SCE version header. */
#define SECTION_EXT_HEADER_TYPE_SCEVERSION 1

/*! SELF versions. */
#define SELF_VERSION_2 2
#define SELF_VERSION_3 3

/*! Supplemental header types. */
/*! SELF control flags. */
#define SPPL_HEADER_TYPE_SELF_CONTROL_FLAGS 1
/*! ELF digest header. */
#define SPPL_HEADER_TYPE_ELF_DIGEST_HEADER 2
/*! NPDRM header. */
#define SPPL_HEADER_TYPE_NPDRM_HEADER 3

/*! Optional header types. */
/*! Capability flags header. */
#define OPT_HEADER_TYPE_CAP_FLAGS 1
/*! Individual seed header. */
#define OPT_HEADER_TYPE_INDIV_SEED 2
/*! Control flags header 4. */
#define OPT_HEADER_TYPE_CONTROL_FLAGS 4

/*! Encryption root header key/iv lengths. */
#define ENCRYPTION_ROOT_KEY_BITS 128
#define ENCRYPTION_ROOT_KEY_LEN 16
#define ENCRYPTION_ROOT_KEY_PAD_LEN 16
#define ENCRYPTION_ROOT_IV_LEN 16
#define ENCRYPTION_ROOT_IV_PAD_LEN 16

/*! Segment cert header types. */
/*! Section headers. */
#define METADATA_SECTION_TYPE_SHDR 1
/*! Program segment. */
#define METADATA_SECTION_TYPE_PHDR 2
/*! Sceversion section. */
#define METADATA_SECTION_TYPE_SCEV 3

/*! Segment types for SELF. */
#define SEGMENT_TYPE_SIGNED_ELF_SECTION_HEADERS 1
#define SEGMENT_TYPE_SIGNED_ELF_PROGRAM_SEGMENT 2
#define SEGMENT_TYPE_SIGNED_ELF_SCEVERSION 3

/*! Segment types for PKG. */
#define SEGMENT_TYPE_UPDATE_PACKAGE_HEADER 1
#define SEGMENT_TYPE_UPDATE_PACKAGE_CONTENTS_HEADER 2
#define SEGMENT_TYPE_UPDATE_PACKAGE 3

/*! Segment types for SPP. */
#define SEGMENT_TYPE_SECURITY_POLICY_PROFILE_HEADER 1
#define SEGMENT_TYPE_SECURITY_POLICY_PROFILE_SEGMENT 2

/*! Segment cert header types for RVK. */
#define SEGMENT_TYPE_REVOKE_LIST_HEADER 1
#define SEGMENT_TYPE_REVOKE_LIST_TABLE 2

/*! Sign algorithms. */
/*! Ecdsa. */
#define SIGN_ALGORITHM_ECDSA 1
/*! Sha1-hmac. */
#define SIGN_ALGORITHM_SHA1_HMAC 2
/*! Sha1. */
#define SIGN_ALGORITHM_SHA1 3

/*! Encryption algorithms. */
/*! Plain-text. */
#define ENC_ALGORITHM_PLAIN 1
/*! Aes128-cbc. */
#define ENC_ALGORITHM_AES128_CBC 2
/*! Aes128-ctr. */
#define ENC_ALGORITHM_AES128_CTR 3
/*! Aes256-cbc. */
#define ENC_ALGORITHM_AES256_CBC 4

/*! Compress algorithms. */
/*! Plain-text. */
#define COMP_ALGORITHM_PLAIN 1
/*! Zlib. */
#define COMP_ALGORITHM_ZLIB 2

/*! Signature sizes. */
/*! Signature S part size. */
#define SIGNATURE_S_SIZE 21
/*! Signature R part size. */
#define SIGNATURE_R_SIZE 21

/*! SCE version not present. */
#define SCE_VERSION_NOT_PRESENT 0
/*! SCE version present. */
#define SCE_VERSION_PRESENT 1

/*! Program types. */
/*! lv0. */
#define PROGRAM_TYPE_LV0 1
/*! lv1. */
#define PROGRAM_TYPE_LV1 2
/*! lv2. */
#define PROGRAM_TYPE_LV2 3
/*! Application. */
#define PROGRAM_TYPE_APP 4
/*! Isolated SPU module. */
#define PROGRAM_TYPE_ISO 5
/*! Secure loader. */
#define PROGRAM_TYPE_LDR 6
/*! Unknown type 7. */
#define PROGRAM_TYPE_UNK_7 7
/*! NPDRM application. */
#define PROGRAM_TYPE_NPDRM 8

/*! NP DRM header magic value ("NPD\0"). */
#define NP_HEADER_MAGIC 0x4E504400

/*! NP DRM types. */
#define NP_DRM_TYPE_NETWORK 1
#define NP_DRM_TYPE_LOCAL 2
#define NP_DRM_TYPE_FREE 3

/*! NPDRM application types. */
#define NP_TYPE_UPDATE 0x20
#define NP_TYPE_SPRX 0
#define NP_TYPE_EXEC 1
#define NP_TYPE_USPRX (NP_TYPE_UPDATE | NP_TYPE_SPRX)
#define NP_TYPE_UEXEC (NP_TYPE_UPDATE | NP_TYPE_EXEC)

/*! Cert file header. */
typedef struct _cert_file_header
{
	/*! Magic value. */
	u32 magic;
	/*! Header version .*/
	u32 version;
	/*! Key revision. */
	u16 attribute;
	/*! File category. */
	u16 category;
	/*! Extended header size. */
	u32 ext_header_size;
	/*! Offset of encapsulated file. */
	u64 file_offset;
	/*! Size of encapsulated file. */
	u64 file_size;
} cert_file_header_t;

/*! SELF header. */
typedef struct _signed_elf_header
{
	/*! SELF version. */
	u64 version;
	/*! Program identification header offset. */
	u64 program_identification_header_offset;
	/*! ELF header offset. */
	u64 elf_header_offset;
	/*! Program headers offset. */
	u64 phdr_offset;
	/*! Section headers offset. */
	u64 shdr_offset;
	/*! Segment ext header offset. */
	u64 segment_ext_header_offset;
	/*! Section ext header offset. */
	u64 section_ext_header_offset;
	/*! Supplemental header offset. */
	u64 supplemental_header_offset;
	/*! Supplemental header size. */
	u64 supplemental_header_size;
	/*! Padding. */
	u64 padding;
} signed_elf_header_t;

/*! Metadata info. */
typedef struct _encryption_root_header
{
	/*! Key. */
	u8 key[ENCRYPTION_ROOT_KEY_LEN];
	/*! Key padding. */
	u8 key_pad[ENCRYPTION_ROOT_KEY_PAD_LEN];
	/*! IV. */
	u8 iv[ENCRYPTION_ROOT_IV_LEN];
	/*! IV padding. */
	u8 iv_pad[ENCRYPTION_ROOT_IV_PAD_LEN];
} encryption_root_header_t;

typedef struct _certification_header
{
	/*! Signature input length. */
	u64 sig_input_length;
	/*! Sign algorithm. */
	u32 sign_algorithm;
	/*! Section count. */
	u32 section_count;
	/*! Key count. */
	u32 key_count;
	/*! Optional header size. */
	u32 opt_header_size;
	u32 unknown_1;
	u32 unknown_2;
} certification_header_t;

/*! Segment certification header. */
typedef struct _segment_certification_header
{
	/*! Data offset. */
	u64 data_offset;
	/*! Data size. */
	u64 data_size;
	/*! Segment type. */
	u32 segment_type;
	/*! Segment id. */
	u32 segment_id;
	/*! Sign algorithm. */
	u32 sign_algorithm;
	/*! Signature index. */
	u32 signature_index;
	/*! Encryption algorithm. */
	u32 enc_algorithm;
	/*! Key index. */
	u32 key_index;
	/*! IV index. */
	u32 iv_index;
	/*! Compress algorithm. */
	u32 comp_algorithm;
} segment_certification_header_t;

/*! SCE file signature. */
typedef struct _signature
{
	u8 r[SIGNATURE_R_SIZE];
	u8 s[SIGNATURE_S_SIZE];
	u8 padding[6];
} signature_t;

/*! Segment info. */
typedef struct _segment_ext_header
{
	u64 offset;
	u64 size;
	u32 comp_algorithm;
	u32 unknown_0;
	u32 unknown_1;
	u32 encrypted;
} segment_ext_header_t;

/*! SCE version. */
typedef struct _section_ext_header
{
	/*! Header type. */
	u32 header_type; // section extended header version
	/*! SCE version section present? */
	u32 present;     // entry count
	/*! Size. */
	u32 size;        //total size
	u32 unknown_3;   //reserved_0
} section_ext_header_t;

/*! SCE version data 0x30. */
typedef struct _sce_version_data_30
{
	u16 unknown_1; //Section idx.
	u16 unknown_2; //Section type?
	u32 unknown_3; //Padding?
	u32 unknown_4; //Number of sections?
	u32 unknown_5; //Padding?
	/*! Data offset. */
	u64 offset;
	/*! Data size. */
	u64 size;
} sce_version_data_30_t;

//(auth_id & AUTH_ONE_MASK) has to be 0x1000000000000000
#define AUTH_ONE_MASK 0xF000000000000000
#define AUTH_TERRITORY_MASK 0x0FF0000000000000
#define VENDER_TERRITORY_MASK 0xFF000000
#define VENDER_ID_MASK 0x00FFFFFF

/*! Program ident header. */
typedef struct _program_identification_header
{
	/*! Auth ID. */
	u64 auth_id;
	/*! Vender ID. */
	u32 vender_id;
	/*! SELF type. */
	u32 program_type;
	/*! Version. */
	u64 version;
	/*! Padding. */
	u64 padding;
} program_identification_header_t;

/*! Vender ID. */
typedef struct _vender_id
{
	u8 territory;
	u8 unknown_1;
	u8 unknown_2;
	u8 gos_id;
} vender_id_t;


/*! Control info. */
typedef struct _supplemental_header
{
	/*! Control info type. */
	u32 type;
	/*! Size of following data. */
	u32 size;
	/*! Next flag (1 if another info follows). */
	u64 next;
} supplemental_header_t;

#define CI_FLAG_00_80 0x80
#define CI_FLAG_00_40 0x40 //root access
#define CI_FLAG_00_20 0x20 //kernel access

#define CI_FLAG_17_01 0x01
#define CI_FLAG_17_02 0x02
#define CI_FLAG_17_04 0x04
#define CI_FLAG_17_08 0x08
#define CI_FLAG_17_10 0x10

//1B:
//bdj 0x01, 0x09
//psp_emu 0x08
//psp_transl 0x0C
#define CI_FLAG_1B_01 0x01 //may use shared mem?
#define CI_FLAG_1B_02 0x02
#define CI_FLAG_1B_04 0x04
#define CI_FLAG_1B_08 0x08 //ss

#define CI_FLAG_1F_SHAREABLE 0x01
#define CI_FLAG_1F_02 0x02 //internal?
#define CI_FLAG_1F_FACTORY 0x04
#define CI_FLAG_1F_08 0x08 //???

/*! Control info data flags. */
typedef struct _ci_data_flags
{
	u8 data[0x20];
} ci_data_flags_t;

/*! Control info data digest 0x30. */
typedef struct _ci_data_digest_30
{
	u8 digest[20];
	u64 unknown_0;
} ci_data_digest_30_t;

/*! Control info data digest 0x40. */
typedef struct _ci_data_digest_40
{
	u8 digest1[20];
	u8 digest2[20];
	u64 fw_version;
} ci_data_digest_40_t;

/*! Control info data NPDRM. */
typedef struct _ci_data_npdrm
{
	/*! Magic. */
	u32 magic;
	/*! Version. */
	u32 version;
	/*! DRM type. */
	u32 drm_type;
	/*! Application type. */
	u32 app_type;
	/*! Content ID. */
	u8 content_id[0x30];
	/*! Random padding. */
	u8 rndpad[0x10];
	/*! ContentID_FileName hash. */
	u8 hash_cid_fname[0x10];
	/*! Control info hash. */
	u8 hash_ci[0x10];
	/*! Start of the Validity period. */
	u64 limited_time_start;
	/*! End of the Validity period. */
	u64 limited_time_end;
} ci_data_npdrm_t;

/*! Optional header. */
typedef struct _opt_header
{
	/*! Type. */
	u32 type;
	/*! Size. */
	u32 size;
	/*! Next flag (1 if another header follows). */
	u64 next;
} opt_header_t;

/*! Capability flags. */
#define CAP_FLAG_1 0x01 //only seen in PPU selfs
#define CAP_FLAG_2 0x02 //only seen in PPU selfs
#define CAP_FLAG_4 0x04 //only seen in bdj PPU self
#define CAP_FLAG_DEH 0x08     //00001000b
#define CAP_FLAG_DEX 0x10     //00010000b
#define CAP_FLAG_CEX 0x20     //00100000b
#define CAP_FLAG_ARCADE 0x40  //01000000b

#define UNK7_2000 0x2000 //hddbind?
#define UNK7_20000 0x20000 //flashbind?
#define UNK7_40000 0x40000 //discbind?
#define UNK7_80000 0x80000

#define UNK7_PS3SWU 0x116000 //dunno...

/*! SCE file capability flags. */
typedef struct _oh_data_cap_flags
{
	u64 unk3; //0
	u64 unk4; //0
	/*! Flags. */
	u64 flags;
	u32 unk6;
	u32 unk7;
} oh_data_cap_flags_t;

/*! Section context. */
typedef struct _sce_section_ctxt
{
	/*! Data buffer. */
	void *buffer;
	/*! Size. */
	u32 size;
	/*! Offset. */
	u32 offset;
	/*! May be compressed. */
	bool may_compr;
} sce_section_ctxt_t;

typedef struct _makeself_ctxt
{
	/*! ELF file buffer (for ELF -> SELF). */
	u8 *elf;
	/*! ELF file length. */
	u32 elf_len;
	/*! ELF header. */
	void *ehdr;
	/*! ELF header size. */
	u32 ehsize;
	/*! Program headers. */
	void *phdrs;
	/*! Program headers size. */
	u32 phsize;
	/*! Section headers. */
	void *shdrs;
	/*! Section headers size. */
	u32 shsize;
	/*! Section info count. */
	u32 si_cnt;
	/*! Number of section infos that are present as data sections. */
	u32 si_sec_cnt;
} makeself_ctxt_t;

/*! SCE file buffer context. */
typedef struct _sce_buffer_ctxt
{
	/*! SCE file buffer. */
	u8 *scebuffer;

	/*! Cert file header. */
	cert_file_header_t *cfh;
	/*! File category dependent header. */
	union
	{
		struct
		{
			/*! SELF header. */
			signed_elf_header_t *selfh;
			/*! Program identification header. */
			program_identification_header_t *ai;
			/*! Segment ext header. */
			segment_ext_header_t *si;
			/*! Section ext header. */
			section_ext_header_t *sv;
			/*! Supplemental headers. */
			list_t *cis;
			/*! Optional headers. */
			list_t *ohs;
		} self;
	};
	/*! Encryption root header. */
	encryption_root_header_t *erh;
	/*! Certification header. */
	certification_header_t *metah;
	/*! Segment certification headers. */
	segment_certification_header_t *metash;
	/*! SCE file keys. */
	u8 *keys;
	/*! Keys length. */
	u32 keys_len;
	/*! Signature. */
	signature_t *sig;

	/*! Metadata decrypted? */
	bool mdec;

	/*! Data layout. */
	/*! Cert file header offset. */
	u32 off_cfh;
	union
	{
		struct
		{
			/*! SELF header offset. */
			u32 off_selfh;
			/*! Program info offset. */
			u32 off_ai;
			/*! ELF header offset. */
			u32 off_ehdr;
			/*! Program header offset. */
			u32 off_phdr;
			/*! Segment info offset. */
			u32 off_si;
			/*! SCE version offset. */
			u32 off_sv;
			/*! Control infos offset. */
			u32 off_cis;
			/*! Optional headers offset. */
			u32 off_ohs;
		} off_self;
	};
	/*! Encryption root header offset. */
	u32 off_erh;
	/*! Certification header offset. */
	u32 off_metah;
	/*! Segment certification headers offset. */
	u32 off_metash;
	/*! Keys offset. */
	u32 off_keys;
	/*! Signature offset. */
	u32 off_sig;
	/*! Header padding end offset. */
	u32 off_hdrpad;

	/*! File creation type dependent data. */
	union
	{
		/*! ELF -> SELF. */
		makeself_ctxt_t *makeself;
	};

	/*! Data sections. */
	list_t *secs;
} sce_buffer_ctxt_t;

/*! Create SCE file context from SCE file buffer. */
sce_buffer_ctxt_t *sce_create_ctxt_from_buffer(u8 *scebuffer);

/*! Create SCE file context for SELF creation. */
sce_buffer_ctxt_t *sce_create_ctxt_build_self(u8 *elf, u32 elf_len);

/*! Add data section to SCE context. */
void sce_add_data_section(sce_buffer_ctxt_t *ctxt, void *buffer, u32 size, bool may_compr);

/*! Set segment certification header. */
void sce_set_segment_certification_header(sce_buffer_ctxt_t *ctxt, u32 segment_type, bool encrypted, u32 idx);

/*! Compress data. */
void sce_compress_data(sce_buffer_ctxt_t *ctxt);

/*! Layout offsets for SCE file creation. */
void sce_layout_ctxt(sce_buffer_ctxt_t *ctxt);

/*! Encrypt context. */
bool sce_encrypt_ctxt(sce_buffer_ctxt_t *ctxt, u8 *keyset);

/*! Write context to file. */
bool sce_write_ctxt(sce_buffer_ctxt_t *ctxt, s8 *fname);

/*! Is certification header encrypted? */
bool is_cert_header_encrypted(sce_buffer_ctxt_t *ctxt);

/*! Decrypt header (use passed metadata_into if not NULL). */
bool sce_decrypt_header(sce_buffer_ctxt_t *ctxt, u8 *metadata_info, u8 *keyset);

/*! Decrypt data. */
bool sce_decrypt_data(sce_buffer_ctxt_t *ctxt);

/*! Print SCE header info. */
void cf_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt);

/*! Print SCE extended header info. */
void cf_ext_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt);

/*! Print SCE encrypted header info. */
void sce_print_encrypted_info(FILE *fp, sce_buffer_ctxt_t *ctxt, u8 *keyset);

/*! Print SCE signature status. */
void print_sce_signature_info(FILE *fp, sce_buffer_ctxt_t *ctxt, u8 *keyset);

/*! Get version string from version. */
s8 *sce_version_to_str(u64 version);

/*! Get version from version string. */
u64 sce_str_to_version(s8 *version);

/*! Convert hex version to dec version. */
u64 sce_hexver_to_decver(u64 version);

/*! Convert dec version to hex version. */
u64 sce_decver_to_hexver(u64 version);

/*! Get supplemental header. */
supplemental_header_t *sce_get_supplemental_header(sce_buffer_ctxt_t *ctxt, u32 type);

/*! Get optional header. */
opt_header_t *sce_get_opt_header(sce_buffer_ctxt_t *ctxt, u32 type);

#endif
