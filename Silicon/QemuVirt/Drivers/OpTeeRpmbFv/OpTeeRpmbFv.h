/** @file

  Copyright (c) 2020, Linaro Ltd. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __OPTEE_RPMB_FV_
#define __OPTEE_RPMB_FV_

#define CREATE_FILE_MAP(x) { #x, x }
enum _RPMB_FILE_MAP {
  EFI_VARS,
  FTW_WORK,
  FTW_SPARE,
};

typedef enum _RPMB_FILE_MAP RPMB_FILE_MAP;

struct _MAP_VAL_TO_FILE {
	CHAR8 *Filename;
	RPMB_FILE_MAP Map;
};

typedef struct _MAP_VAL_TO_FILE MAP_VAL_TO_FILE;

struct _MEM_INSTANCE
{
    UINT32                              Signature;
    EFI_HANDLE                          Handle;

    BOOLEAN                             Initialized;

    EFI_PHYSICAL_ADDRESS                MemBaseAddress;
    UINT16                              BlockSize;
    UINT16                              NBlocks;
    EFI_LBA                             StartLba;

    EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  FvbProtocol;
};

typedef struct _MEM_INSTANCE            MEM_INSTANCE;

/* SVC Args */
#define SP_SVC_RPMB_READ                0xC4000066
#define SP_SVC_RPMB_WRITE               0xC4000067

#define NBLOCKS                    (3 * 4) // EFI Vars, FTW working, FTW spare
#define BLOCK_SIZE                 SIZE_4KB
#define FLASH_SIGNATURE            SIGNATURE_32('r', 'p', 'm', 'b')
#define INSTANCE_FROM_FVB_THIS(a)  CR(a, MEM_INSTANCE, FvbProtocol, \
					FLASH_SIGNATURE)

#endif
