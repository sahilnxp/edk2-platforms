/** @file

  Copyright (c) 2020, Linaro Ltd. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EEPROM_FVB_
#define __EEPROM_FVB_

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

#define NBLOCKS                    (3 * 1) // EFI Vars, FTW working, FTW spare
#define BLOCK_SIZE                 SIZE_64KB

#define FLASH_SIGNATURE            SIGNATURE_32('e', 'e', 'p', 'r', 'o', 'm')
#define INSTANCE_FROM_FVB_THIS(a)  CR(a, MEM_INSTANCE, FvbProtocol, \
					FLASH_SIGNATURE)

/* Since there are 4 logical blocks of size 64KB each in EEPROM which can be accessed with
  * specific slave addres 0x54-0x57, we will use single block for Variable, FTW Working,
  * FTW Spare Space */
#define EEPROM_VARIABLE_STORE_ADDR			0x54
#define EEPROM_FTW_WORKING_SPACE_ADDR		0x55
#define EEPROM_FTW_SPARE_SPACE_ADDR		0x56

#define EEPROM_ADDR_WIDTH_1BYTE		0x1
#define EEPROM_ADDR_WIDTH_2BYTES	0x2
#define EEPROM_ADDR_WIDTH_3BYTES	0x3

EFI_STATUS
Eeprom_Write (IN  UINT32  SlaveAddress, IN  UINT64  RegAddress,
  IN  UINT8   RegAddressWidthInBytes, IN  UINT8   *RegValue,
  IN  UINT32  RegValueNumBytes);

EFI_STATUS
Eeprom_Read (IN  UINT32  SlaveAddress, IN  UINT64  RegAddress,
  IN  UINT8   RegAddressWidthInBytes, IN  UINT8   *RegValue,
  IN  UINT32  RegValueNumBytes);


#endif
