/*++ @file  EepromFvb.c

 Copyright 2020 NXP

 This program and the accompanying materials
 are licensed and made available under the terms and conditions of the BSD License
 which accompanies this distribution.  The full text of the license may be found at
 http://opensource.org/licenses/bsd-license.php

 THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

 --*/

#include <PiDxe.h>

#include <Guid/SystemNvDataGuid.h>
#include <Guid/VariableFormat.h>
#include <Library/BaseLib.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/SocClockLib.h>
#include <Library/I2cLib.h>
#include <Library/MmServicesTableLib.h>

#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/SmmFirmwareVolumeBlock.h>

#include "EepromFvb.h"

#define EEPROM_FUNC 1

UINTN        I2cBase = 0;

STATIC MEM_INSTANCE  mInstance;

static void hexdump(const char *label, const char *cp, int len)
{
    DEBUG ((DEBUG_INFO, "%s=", label));

    while (len--) {
	DEBUG ((DEBUG_INFO, "%02X ",  0xff & *cp++));
	if (!(len % 16))
	  DEBUG ((DEBUG_INFO, "\n"));
    }

    DEBUG ((DEBUG_INFO, "\n"));

}
STATIC
VOID DbgMem (
  CHAR8  *Prefix,
  EFI_PHYSICAL_ADDRESS  Addr
  )
{

  EFI_PHYSICAL_ADDRESS NewAddr = Addr;
  UINTN Size = FixedPcdGet32(PcdFlashNvStorageVariableSize); // FIXME add size for all

  DEBUG ((DEBUG_INFO, "%a: %a EFIVARS:\n", __FUNCTION__, Prefix));
  hexdump("", (char*)NewAddr, 0x80);
  DEBUG ((DEBUG_INFO, "%a: %a FTWWORK:\n", __FUNCTION__, Prefix));
  hexdump("", (char*)NewAddr+ Size, 0x80);
  DEBUG ((DEBUG_INFO, "%a: %a FTW_SPARE:\n", __FUNCTION__, Prefix));
  hexdump("", (char*)NewAddr+ (2*Size), 0x80);
}

//STATIC EFI_EVENT mFvbVirtualAddrChangeEvent;

/* FIXME: Since EEPROM is not memory-mapped we will keep this as 0 */
/**
 The GetAttributes() function retrieves the attributes and
 current settings of the block.

 @param This         Indicates the EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL instance.

 @param Attributes   Pointer to EFI_FVB_ATTRIBUTES_2 in which the attributes and
                     current settings are returned.
                     Type EFI_FVB_ATTRIBUTES_2 is defined in EFI_FIRMWARE_VOLUME_HEADER.

 @retval EFI_SUCCESS The firmware volume attributes were returned.

 **/
EFI_STATUS
EFIAPI
FvbGetAttributes(
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL    *This,
  OUT       EFI_FVB_ATTRIBUTES_2                   *Attributes
  )
{
  EFI_FVB_ATTRIBUTES_2  FlashFvbAttributes;

  FlashFvbAttributes = (EFI_FVB_ATTRIBUTES_2) (

      EFI_FVB2_READ_ENABLED_CAP | // Reads may be enabled
      EFI_FVB2_READ_STATUS      | // Reads are currently enabled
      EFI_FVB2_STICKY_WRITE     | // A block erase is required to flip bits into EFI_FVB2_ERASE_POLARITY
      EFI_FVB2_MEMORY_MAPPED    | // It is memory mapped
      EFI_FVB2_ERASE_POLARITY   |  // After erasure all bits take this value (i.e. '1')
      EFI_FVB2_WRITE_STATUS     | // Writes are currently enabled
      EFI_FVB2_WRITE_ENABLED_CAP  // Writes may be enabled
      );

  *Attributes = FlashFvbAttributes;

//  DEBUG ((DEBUG_BLKIO, "FvbGetAttributes(0x%X)\n", *Attributes));

  return EFI_SUCCESS;
}

/**
 The SetAttributes() function sets configurable firmware volume attributes
 and returns the new settings of the firmware volume.


 @param This                     Indicates the EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL instance.

 @param Attributes               On input, Attributes is a pointer to EFI_FVB_ATTRIBUTES_2
                                 that contains the desired firmware volume settings.
                                 On successful return, it contains the new settings of
                                 the firmware volume.
                                 Type EFI_FVB_ATTRIBUTES_2 is defined in EFI_FIRMWARE_VOLUME_HEADER.

 @retval EFI_SUCCESS             The firmware volume attributes were returned.

 @retval EFI_INVALID_PARAMETER   The attributes requested are in conflict with the capabilities
                                 as declared in the firmware volume header.

 **/
EFI_STATUS
EFIAPI
FvbSetAttributes(
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL  *This,
  IN OUT    EFI_FVB_ATTRIBUTES_2                 *Attributes
  )
{
 // DEBUG ((DEBUG_ERROR, "FvbSetAttributes(0x%X) is not supported\n",*Attributes));
  return EFI_SUCCESS;
}

/**
 The GetPhysicalAddress() function retrieves the base address of
 a memory-mapped firmware volume. This function should be called
 only for memory-mapped firmware volumes.

 @param This               Indicates the EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL instance.

 @param Address            Pointer to a caller-allocated
                           EFI_PHYSICAL_ADDRESS that, on successful
                           return from GetPhysicalAddress(), contains the
                           base address of the firmware volume.

 @retval EFI_SUCCESS       The firmware volume base address was returned.

 @retval EFI_NOT_SUPPORTED The firmware volume is not memory mapped.

 **/
EFI_STATUS
EFIAPI
FvbGetPhysicalAddress (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL  *This,
  OUT       EFI_PHYSICAL_ADDRESS                 *Address
  )
{
 // DEBUG ((DEBUG_ERROR, "############ FvbGetPhysicalAddress \n"));
  MEM_INSTANCE *Instance;

  Instance = INSTANCE_FROM_FVB_THIS(This);
  *Address = Instance->MemBaseAddress;

  return EFI_SUCCESS;
}

/**
  Write data to I2C EEPROM.

  @param[in]  Base                   Base Address of I2c controller's registers
  @param[in]  SlaveAddress           Logical Address of EEPROM block.
  @param[in]  RegAddress             Register Address in Slave's memory map
  @param[in]  RegAddressWidthInBytes Number of bytes in RegAddress to send to
                                     I2c Slave for simple reads without any
                                     register, make this value = 0
                                     (RegAddress is don't care in that case)
  @param[out] RegValue               Value to be read from I2c slave's regiser
  @param[in]  RegValueNumBytes       Number of bytes to read from I2c slave
                                     register

  @return  EFI_SUCCESS       successfuly read the registers
  @return  EFI_DEVICE_ERROR  There was an error while transferring data through
                             I2c bus
  @return  EFI_NO_RESPONSE   There was no Ack from i2c device
  @return  EFI_TIMEOUT       I2c Bus is busy
  @return  EFI_NOT_READY     I2c Bus Arbitration lost
**/
EFI_STATUS
EFIAPI
Eeprom_Write (
  IN  UINT32  SlaveAddress,
  IN  UINT64  RegAddress,
  IN  UINT8   RegAddressWidthInBytes,
  IN  UINT8   *RegValue,
  IN  UINT32  RegValueNumBytes
  )
{
  EFI_I2C_OPERATION       *Operations;
  EFI_I2C_REQUEST_PACKET         RequestPacket;
  UINTN                   OperationCount;
  UINT8                   Address[sizeof (RegAddress)];
  UINT8                   *PtrAddress;
  EFI_STATUS              Status;

  Status = EFI_SUCCESS;

  ZeroMem (&RequestPacket, sizeof (RequestPacket));
  OperationCount = 0;
  Operations = RequestPacket.Operation;
  PtrAddress = Address;

  if (RegAddressWidthInBytes > ARRAY_SIZE (Address)) {
    return EFI_INVALID_PARAMETER;
  }

  if (RegAddressWidthInBytes != 0) {
    Operations[OperationCount].LengthInBytes = RegAddressWidthInBytes;
    Operations[OperationCount].Buffer = PtrAddress;
    while (RegAddressWidthInBytes--) {
      *PtrAddress++ = RegAddress >> (8 * RegAddressWidthInBytes);
    }
    OperationCount++;
  }

  Operations[OperationCount].LengthInBytes = RegValueNumBytes;
  Operations[OperationCount].Buffer = RegValue;
  Operations[OperationCount].Flags = 0;
  OperationCount++;

  RequestPacket.OperationCount = OperationCount;

  Status = I2cBusXfer(I2cBase, SlaveAddress, &RequestPacket);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "I2cBusXfer Failed while Writing data\n"));
    return Status;
  }

  return Status;
}


/**
  Read data from I2C EEPROM.

  @param[in]  Base                   Base Address of I2c controller's registers
  @param[in]  SlaveAddress           Logical Address of EEPROM block.
  @param[in]  RegAddress             Register Address in Slave's memory map
  @param[in]  RegAddressWidthInBytes Number of bytes in RegAddress to send to
                                     I2c Slave for simple reads without any
                                     register, make this value = 0
                                     (RegAddress is don't care in that case)
  @param[out] RegValue               Value to be read from I2c slave's regiser
  @param[in]  RegValueNumBytes       Number of bytes to read from I2c slave
                                     register

  @return  EFI_SUCCESS       successfuly read the registers
  @return  EFI_DEVICE_ERROR  There was an error while transferring data through
                             I2c bus
  @return  EFI_NO_RESPONSE   There was no Ack from i2c device
  @return  EFI_TIMEOUT       I2c Bus is busy
  @return  EFI_NOT_READY     I2c Bus Arbitration lost
**/
EFI_STATUS
EFIAPI
Eeprom_Read (
  IN  UINT32  SlaveAddress,
  IN  UINT64  RegAddress,
  IN  UINT8   RegAddressWidthInBytes,
  IN OUT UINT8   *RegValue,
  IN  UINT32  RegValueNumBytes
  )
{
  EFI_I2C_OPERATION       *Operations;
  EFI_I2C_REQUEST_PACKET         RequestPacket;
  UINTN                   OperationCount;
  UINT8                   Address[sizeof (RegAddress)];
  UINT8                   *PtrAddress;
  EFI_STATUS              Status;

  Status = EFI_SUCCESS;
  DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  ZeroMem (&RequestPacket, sizeof (RequestPacket));
  OperationCount = 0;
  Operations = RequestPacket.Operation;
  PtrAddress = Address;

  if (RegAddressWidthInBytes > ARRAY_SIZE (Address)) {
    return EFI_INVALID_PARAMETER;
  }
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  if (RegAddressWidthInBytes != 0) {
    Operations[OperationCount].LengthInBytes = RegAddressWidthInBytes;
    Operations[OperationCount].Buffer = PtrAddress;
    while (RegAddressWidthInBytes--) {
      *PtrAddress++ = RegAddress >> (8 * RegAddressWidthInBytes);
    }
    OperationCount++;
  }
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  Operations[OperationCount].LengthInBytes = RegValueNumBytes;
  Operations[OperationCount].Buffer = RegValue;
  Operations[OperationCount].Flags = I2C_FLAG_READ;
  OperationCount++;
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  RequestPacket.OperationCount = OperationCount;

  Status = I2cBusXfer(I2cBase, SlaveAddress, &RequestPacket);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "I2cBusXfer Failed while reading data\n"));
    return Status;
  }

  return Status;
}

/**
 Reads the specified number of bytes into a buffer from the specified block.

 The Read() function reads the requested number of bytes from the
 requested block and stores them in the provided buffer.
 Implementations should be mindful that the firmware volume
 might be in the ReadDisabled state. If it is in this state,
 the Read() function must return the status code
 EFI_ACCESS_DENIED without modifying the contents of the
 buffer. The Read() function must also prevent spanning block
 boundaries. If a read is requested that would span a block
 boundary, the read must read up to the boundary but not
 beyond. The output parameter NumBytes must be set to correctly
 indicate the number of bytes actually read. The caller must be
 aware that a read may be partially completed.

 @param This                 Indicates the EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL instance.

 @param Lba                  The starting logical block index from which to read.

 @param Offset               Offset into the block at which to begin reading.

 @param NumBytes             Pointer to a UINTN.
                             At entry, *NumBytes contains the total size of the buffer.
                             At exit, *NumBytes contains the total number of bytes read.

 @param Buffer               Pointer to a caller-allocated buffer that will be used
                             to hold the data that is read.

 @retval EFI_SUCCESS         The firmware volume was read successfully,  and contents are
                             in Buffer.

 @retval EFI_BAD_BUFFER_SIZE Read attempted across an LBA boundary.
                             On output, NumBytes contains the total number of bytes
                             returned in Buffer.

 @retval EFI_ACCESS_DENIED   The firmware volume is in the ReadDisabled state.

 @retval EFI_DEVICE_ERROR    The block device is not functioning correctly and could not be read.

 **/
EFI_STATUS
EFIAPI
FvbRead (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL   *This,
  IN        EFI_LBA                               Lba,
  IN        UINTN                                 Offset,
  IN OUT    UINTN                                 *NumBytes,
  IN OUT    UINT8                                 *Buffer
  )
{
  UINTN                       BlockSize;
  EFI_STATUS                  Status = EFI_SUCCESS;
  EFI_STATUS                  TmpStatus;
  VOID         *Base;
  UINT64       Eeprom_addr = 0;
  TmpStatus = EFI_SUCCESS;

  MEM_INSTANCE		*Instance;

  Instance = INSTANCE_FROM_FVB_THIS(This);

  // Cache the block size to avoid de-referencing pointers all the time
  BlockSize = Instance->BlockSize;
#if 0
  DEBUG ((
    DEBUG_ERROR,
    "FvbRead(Parameters: Lba=%ld, Offset=0x%x, *NumBytes=0x%x, Buffer @ 0x%08x), BlockSize=0x%x\n",
    Lba, Offset, *NumBytes, Buffer, BlockSize
    ));
#endif
  // The read must not span block boundaries.
  // We need to check each variable individually because adding two large values together overflows.
  if (Offset >= BlockSize) {
    DEBUG ((DEBUG_ERROR, "FvbRead: ERROR - EFI_BAD_BUFFER_SIZE: (Offset=0x%x + NumBytes=0x%x) > BlockSize=0x%x\n", Offset, *NumBytes, BlockSize ));
    *NumBytes = 0;
    return EFI_BAD_BUFFER_SIZE;
  }

  // We must have some bytes to read
  if (*NumBytes == 0) {
  	DEBUG ((DEBUG_ERROR, "%a Numbyes == 0\n", __FUNCTION__));
    return EFI_BAD_BUFFER_SIZE;
  }

  if ((Offset + *NumBytes) > BlockSize) {
	  	DEBUG ((DEBUG_ERROR, "%a Offset + *NumBytes) > BlockSize\n", __FUNCTION__));
    *NumBytes = BlockSize - Offset;
    TmpStatus = EFI_BAD_BUFFER_SIZE;
  }

  Base = (VOID *)Instance->MemBaseAddress + Lba * BlockSize + Offset;
  // Update the memory copy
  CopyMem (Buffer, Base, *NumBytes);

  Eeprom_addr = Lba * BlockSize + Offset;

#if EEPROM_FUNC
  Status = Eeprom_Read(EEPROM_VARIABLE_STORE_ADDR, Eeprom_addr,
  			EEPROM_ADDR_WIDTH_2BYTES, Buffer, *NumBytes);
  if (!EFI_ERROR(Status)) {
    return TmpStatus;
  } else {
    DEBUG ((DEBUG_ERROR, "Eeprom_Read returned %r\n", Status));
    Status = EFI_DEVICE_ERROR;
  }
#endif
  return Status;
}

/**
 Writes the specified number of bytes from the input buffer to the block.

 The Write() function writes the specified number of bytes from
 the provided buffer to the specified block and offset. If the
 firmware volume is sticky write, the caller must ensure that
 all the bits of the specified range to write are in the
 EFI_FVB_ERASE_POLARITY state before calling the Write()
 function, or else the result will be unpredictable. This
 unpredictability arises because, for a sticky-write firmware
 volume, a write may negate a bit in the EFI_FVB_ERASE_POLARITY
 state but cannot flip it back again.  Before calling the
 Write() function,  it is recommended for the caller to first call
 the EraseBlocks() function to erase the specified block to
 write. A block erase cycle will transition bits from the
 (NOT)EFI_FVB_ERASE_POLARITY state back to the
 EFI_FVB_ERASE_POLARITY state. Implementations should be
 mindful that the firmware volume might be in the WriteDisabled
 state. If it is in this state, the Write() function must
 return the status code EFI_ACCESS_DENIED without modifying the
 contents of the firmware volume. The Write() function must
 also prevent spanning block boundaries. If a write is
 requested that spans a block boundary, the write must store up
 to the boundary but not beyond. The output parameter NumBytes
 must be set to correctly indicate the number of bytes actually
 written. The caller must be aware that a write may be
 partially completed. All writes, partial or otherwise, must be
 fully flushed to the hardware before the Write() service
 returns.

 @param This                 Indicates the EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL instance.

 @param Lba                  The starting logical block index to write to.

 @param Offset               Offset into the block at which to begin writing.

 @param NumBytes             The pointer to a UINTN.
                             At entry, *NumBytes contains the total size of the buffer.
                             At exit, *NumBytes contains the total number of bytes actually written.

 @param Buffer               The pointer to a caller-allocated buffer that contains the source for the write.

 @retval EFI_SUCCESS         The firmware volume was written successfully.

 @retval EFI_BAD_BUFFER_SIZE The write was attempted across an LBA boundary.
                             On output, NumBytes contains the total number of bytes
                             actually written.

 @retval EFI_ACCESS_DENIED   The firmware volume is in the WriteDisabled state.

 @retval EFI_DEVICE_ERROR    The block device is malfunctioning and could not be written.


 **/
EFI_STATUS
EFIAPI
FvbWrite (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL   *This,
  IN        EFI_LBA                               Lba,
  IN        UINTN                                 Offset,
  IN OUT    UINTN                                 *NumBytes,
  IN        UINT8                                 *Buffer
  )
{
  UINTN                       BlockSize;

  EFI_STATUS                  Status = EFI_SUCCESS;
  EFI_STATUS                  TmpStatus;

  TmpStatus = EFI_SUCCESS;
  MEM_INSTANCE		*Instance;
  VOID*              Base;
  UINT64             Eeprom_addr = 0;

  Instance = INSTANCE_FROM_FVB_THIS(This);

  // Cache the block size to avoid de-referencing pointers all the time
  BlockSize = Instance->BlockSize;
#if 0
  DEBUG ((
    DEBUG_ERROR,
    "FvWrite(Parameters: Lba=%ld, Offset=0x%x, *NumBytes=0x%x, Buffer @ 0x%08x), BlockSize=0x%x\n",
    Lba, Offset, *NumBytes, Buffer, BlockSize
    ));
#endif

  // The read must not span block boundaries.
  // We need to check each variable individually because adding two large values together overflows.
  if (Offset >= BlockSize) {
    DEBUG ((DEBUG_ERROR, "FvbWrite: ERROR - EFI_BAD_BUFFER_SIZE: (Offset=0x%x + NumBytes=0x%x) > BlockSize=0x%x\n", Offset, *NumBytes, BlockSize ));
    *NumBytes = 0;
    return EFI_BAD_BUFFER_SIZE;
  }

  // We must have some bytes to write
  if (*NumBytes == 0) {
  	DEBUG ((DEBUG_ERROR, "NumBytes = 0000000000000000000000\n"));
    return EFI_BAD_BUFFER_SIZE;
  }

  if ((Offset + *NumBytes) > BlockSize) {
  	DEBUG ((DEBUG_ERROR, "**********************\n"));
    *NumBytes = BlockSize - Offset;
    TmpStatus = EFI_BAD_BUFFER_SIZE;
  }
  Base = (VOID *)Instance->MemBaseAddress + Lba * BlockSize + Offset;
    // FIXME make op-tee report write failures on a register and abort the in-memory update
  // if writing the RPMB fails + return the correct status
  // Update the memory copy
  CopyMem (Base, Buffer, *NumBytes);
  Eeprom_addr = Lba * BlockSize + Offset;

#if EEPROM_FUNC
  Status = Eeprom_Write(EEPROM_VARIABLE_STORE_ADDR, Eeprom_addr,
  			EEPROM_ADDR_WIDTH_2BYTES, Buffer, *NumBytes);
  if (!EFI_ERROR(Status)) {
    return TmpStatus;
  } else {
    DEBUG ((DEBUG_ERROR, "Eeprom_Write returned %r\n", Status));
    Status = EFI_DEVICE_ERROR;
  }
#endif
  return Status;
}

/**
 Erases and initialises a firmware volume block.

 The EraseBlocks() function erases one or more blocks as denoted
 by the variable argument list. The entire parameter list of
 blocks must be verified before erasing any blocks. If a block is
 requested that does not exist within the associated firmware
 volume (it has a larger index than the last block of the
 firmware volume), the EraseBlocks() function must return the
 status code EFI_INVALID_PARAMETER without modifying the contents
 of the firmware volume. Implementations should be mindful that
 the firmware volume might be in the WriteDisabled state. If it
 is in this state, the EraseBlocks() function must return the
 status code EFI_ACCESS_DENIED without modifying the contents of
 the firmware volume. All calls to EraseBlocks() must be fully
 flushed to the hardware before the EraseBlocks() service
 returns.

 @param This                     Indicates the EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL
 instance.

 @param ...                      The variable argument list is a list of tuples.
                                 Each tuple describes a range of LBAs to erase
                                 and consists of the following:
                                 - An EFI_LBA that indicates the starting LBA
                                 - A UINTN that indicates the number of blocks to erase.

                                 The list is terminated with an EFI_LBA_LIST_TERMINATOR.
                                 For example, the following indicates that two ranges of blocks
                                 (5-7 and 10-11) are to be erased:
                                 EraseBlocks (This, 5, 3, 10, 2, EFI_LBA_LIST_TERMINATOR);

 @retval EFI_SUCCESS             The erase request successfully completed.

 @retval EFI_ACCESS_DENIED       The firmware volume is in the WriteDisabled state.

 @retval EFI_DEVICE_ERROR        The block device is not functioning correctly and could not be written.
                                 The firmware device may have been partially erased.

 @retval EFI_INVALID_PARAMETER   One or more of the LBAs listed in the variable argument list do
                                 not exist in the firmware volume.

 **/
EFI_STATUS
EFIAPI
FvbEraseBlocks (
  IN CONST EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *This,
  ...
  )
{
//  DEBUG ((DEBUG_ERROR, "********************* FvbEraseBlocks unsupported for now\n"));
//  return EFI_UNSUPPORTED;

   VA_LIST       Args;
  EFI_LBA       Start;
  UINTN         Length;
  MEM_INSTANCE *Instance;
  UINTN NumBytes;
//  CHAR8        *File;
//  VOID         *Base;
//  UINTN         RelativeOffset;

  Instance = INSTANCE_FROM_FVB_THIS(This);

  VA_START (Args, This);
  for (Start = VA_ARG (Args, EFI_LBA);
       Start != EFI_LBA_LIST_TERMINATOR;
       Start = VA_ARG (Args, EFI_LBA)) {
    Length = VA_ARG (Args, UINTN);
  NumBytes = Length * BLOCK_SIZE;
  // FIXME first write then set the in memory buffer
  SetMem64 ((VOID *)Instance->MemBaseAddress + Start * BLOCK_SIZE, Length * BLOCK_SIZE, ~0UL);
//  Base = (VOID *)Instance->MemBaseAddress + Start * BLOCK_SIZE;
//  File = GetFileAndOffset (Base, &RelativeOffset);
//  SendSvc (SP_SVC_RPMB_WRITE, File, (UINTN) Base, NumBytes, RelativeOffset);
  //DEBUG ((EFI_D_INFO, "%a Erase %lu LEN %lu Buf %p\n", __func__, Start, Length, Base));
  //OpTeeRpmbFvWrite(&Instance->FvbProtocol, Start , 0, &NumBytes, Base);
  }

  VA_END (Args);

  return EFI_SUCCESS;
#if 0
  EFI_STATUS                  Status;
  VA_LIST                     Args;
  UINTN                       BlockOffset; // Offset of Lba to erase
  EFI_LBA                     StartingLba; // Lba from which we start erasing
  UINTN                       NumOfLba; // Number of Lba blocks to erase
  MEM_INSTANCE		*Instance;

  Instance = INSTANCE_FROM_FVB_THIS(This);

  DEBUG ((DEBUG_BLKIO, "FvbEraseBlocks()\n"));

  Status = EFI_SUCCESS;

  // Before erasing, check the entire list of parameters to ensure all specified blocks are valid
  VA_START (Args, This);
  do {
    // Get the Lba from which we start erasing
    StartingLba = VA_ARG (Args, EFI_LBA);

    // Have we reached the end of the list?
    if (StartingLba == EFI_LBA_LIST_TERMINATOR) {
      //Exit the while loop
      break;
    }

    // How many Lba blocks are we requested to erase?
    NumOfLba = VA_ARG (Args, UINTN);

    // All blocks must be within range
    DEBUG ((
      DEBUG_BLKIO,
      "FvbEraseBlocks: Check if: ( StartingLba=%ld + NumOfLba=%Lu - 1 ) > LastBlock=%ld.\n",
      StartingLba,
      (UINT64)NumOfLba,
      Context->LastLba
      ));
    if ((NumOfLba == 0) || ((StartingLba + NumOfLba - 1) > Context->LastLba)) {
      VA_END (Args);
      DEBUG ((DEBUG_ERROR, "FvbEraseBlocks: ERROR - Lba range goes past the last Lba.\n"));
      Status = EFI_INVALID_PARAMETER;
      goto EXIT;
    }
  } while (TRUE);
  VA_END (Args);

  //
  // To get here, all must be ok, so start erasing
  //
  VA_START (Args, This);
  do {
    // Get the Lba from which we start erasing
    StartingLba = VA_ARG (Args, EFI_LBA);

    // Have we reached the end of the list?
    if (StartingLba == EFI_LBA_LIST_TERMINATOR) {
      // Exit the while loop
      break;
    }

    // How many Lba blocks are we requested to erase?
    NumOfLba = VA_ARG (Args, UINTN);

    // Go through each one and erase it
    while (NumOfLba > 0) {

      // Get the offset of Lba to erase
      //FIXME: Set the BlockOffset
      BlockOffset = GET_BLOCK_OFFSET(StartingLba);

      // Erase it
      DEBUG ((
        DEBUG_BLKIO,
        "FvbEraseBlocks: Erasing Lba=%ld @ Offset 0x%08x.\n",
        StartingLba, BlockOffset
        ));
	//FIXME: Since we have kept the Block Size to be 64KB, so there is only 1 block which will
	//be erased. So whole block will be erased. For now not supporting the FvbEraseBlocks.
//	Status = Eeprom_Write();
	if (EFI_ERROR (Status)) {
        VA_END (Args);
        Status = EFI_DEVICE_ERROR;
        goto EXIT;
      }

      // Move to the next Lba
      StartingLba++;
      NumOfLba--;
    }
  } while (TRUE);
  VA_END (Args);

EXIT:
  return Status;
#endif
}

/**
 The GetBlockSize() function retrieves the size of the requested
 block. It also returns the number of additional blocks with
 the identical size. The GetBlockSize() function is used to
 retrieve the block map (see EFI_FIRMWARE_VOLUME_HEADER).


 @param This                     Indicates the EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL instance.

 @param Lba                      Indicates the block for which to return the size.

 @param BlockSize                Pointer to a caller-allocated UINTN in which
                                 the size of the block is returned.

 @param NumberOfBlocks           Pointer to a caller-allocated UINTN in
                                 which the number of consecutive blocks,
                                 starting with Lba, is returned. All
                                 blocks in this range have a size of
                                 BlockSize.


 @retval EFI_SUCCESS             The firmware volume base address was returned.

 @retval EFI_INVALID_PARAMETER   The requested LBA is out of range.

 **/
STATIC
EFI_STATUS
FvbGetBlockSize (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  IN        EFI_LBA                            Lba,
  OUT       UINTN                              *BlockSize,
  OUT       UINTN                              *NumberOfBlocks
  )
{
  MEM_INSTANCE *Instance;

  Instance = INSTANCE_FROM_FVB_THIS(This);
  *BlockSize = Instance->BlockSize;
  *NumberOfBlocks = Instance->NBlocks;

  return EFI_SUCCESS;
}

/**
  Reads the specified number of bytes into a buffer from the specified block.

  The Read() function reads the requested number of bytes from the
  requested block and stores them in the provided buffer.
  Implementations should be mindful that the firmware volume
  might be in the ReadDisabled state. If it is in this state,
  the Read() function must return the status code
  EFI_ACCESS_DENIED without modifying the contents of the
  buffer. The Read() function must also prevent spanning block
  boundaries. If a read is requested that would span a block
  boundary, the read must read up to the boundary but not
  beyond. The output parameter NumBytes must be set to correctly
  indicate the number of bytes actually read. The caller must be
  aware that a read may be partially completed.

  @param This     Indicates the EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL instance.

  @param Lba      The starting logical block index
                  from which to read.

  @param Offset   Offset into the block at which to begin reading.

  @param NumBytes Pointer to a UINTN. At entry, *NumBytes
                  contains the total size of the buffer. At
                  exit, *NumBytes contains the total number of
                  bytes read.

  @param Buffer   Pointer to a caller-allocated buffer that will
                  be used to hold the data that is read.

  @retval EFI_SUCCESS         The firmware volume was read successfully,
                              and contents are in Buffer.

  @retval EFI_BAD_BUFFER_SIZE Read attempted across an LBA
                              boundary. On output, NumBytes
                              contains the total number of bytes
                              returned in Buffer.

  @retval EFI_ACCESS_DENIED   The firmware volume is in the
                              ReadDisabled state.

  @retval EFI_DEVICE_ERROR    The block device is not
                              functioning correctly and could
                              not be read.

**/
#if EEPROM_FUNC
STATIC
VOID
PreRead (
  EFI_PHYSICAL_ADDRESS Addr
 )
{
  // FIXME  Clean this up with proper definitions and remove the hardcoded
  // filenames
  EFI_STATUS Status = EFI_SUCCESS;
  EFI_PHYSICAL_ADDRESS NewAddr = Addr;
  UINTN Size = 0;

  UINTN StartOffset = 0x0;
  
  Size = FixedPcdGet32(PcdFlashNvStorageVariableSize); // FIXME add size for all
  DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  Status = Eeprom_Read(EEPROM_VARIABLE_STORE_ADDR, StartOffset,
  				EEPROM_ADDR_WIDTH_2BYTES, (UINT8 *)NewAddr, Size);
  if (EFI_ERROR(Status))
  	DEBUG ((DEBUG_ERROR, "Eeprom_Read failed for Variables\n"));

  DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  Status = Eeprom_Read(EEPROM_FTW_WORKING_SPACE_ADDR, StartOffset,
  				EEPROM_ADDR_WIDTH_2BYTES, (UINT8 *)(NewAddr + Size), Size);
    if (EFI_ERROR(Status))
  	DEBUG ((DEBUG_ERROR, "Eeprom_Read failed for FTW Working Space\n"));

  Status = Eeprom_Read(EEPROM_FTW_SPARE_SPACE_ADDR, StartOffset,
  				EEPROM_ADDR_WIDTH_2BYTES, (UINT8 *)(NewAddr + (2 * Size)), Size);
    if (EFI_ERROR(Status))
  	DEBUG ((DEBUG_ERROR, "Eeprom_Read failed for FTW Spare Space\n"));

}
#endif
#if 0
/**
  Erases and initializes a firmware volume block.

  The EraseBlocks() function erases one or more blocks as denoted
  by the variable argument list. The entire parameter list of
  blocks must be verified before erasing any blocks. If a block is
  requested that does not exist within the associated firmware
  volume (it has a larger index than the last block of the
  firmware volume), the EraseBlocks() function must return the
  status code EFI_INVALID_PARAMETER without modifying the contents
  of the firmware volume. Implementations should be mindful that
  the firmware volume might be in the WriteDisabled state. If it
  is in this state, the EraseBlocks() function must return the
  status code EFI_ACCESS_DENIED without modifying the contents of
  the firmware volume. All calls to EraseBlocks() must be fully
  flushed to the hardware before the EraseBlocks() service
  returns.

  @param This   Indicates the EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL
                instance.

  @param ...    The variable argument list is a list of tuples.
                Each tuple describes a range of LBAs to erase
                and consists of the following:
                - An EFI_LBA that indicates the starting LBA
                - A UINTN that indicates the number of blocks to
                  erase.

                The list is terminated with an
                EFI_LBA_LIST_TERMINATOR. For example, the
                following indicates that two ranges of blocks
                (5-7 and 10-11) are to be erased: EraseBlocks
                (This, 5, 3, 10, 2, EFI_LBA_LIST_TERMINATOR);

  @retval EFI_SUCCESS The erase request successfully
                      completed.

  @retval EFI_ACCESS_DENIED   The firmware volume is in the
                              WriteDisabled state.
  @retval EFI_DEVICE_ERROR  The block device is not functioning
                            correctly and could not be written.
                            The firmware device may have been
                            partially erased.
  @retval EFI_INVALID_PARAMETER One or more of the LBAs listed
                                in the variable argument list do
                                not exist in the firmware volume.

**/
STATIC
EFI_STATUS
FvbEraseBlocks (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  ...
  )
{
  VA_LIST       Args;
  EFI_LBA       Start;
  UINTN         Length;
  MEM_INSTANCE *Instance;
  UINTN NumBytes;
  CHAR8        *File;
  VOID         *Base;
  UINTN         RelativeOffset;

  Instance = INSTANCE_FROM_FVB_THIS(This);

  VA_START (Args, This);
  for (Start = VA_ARG (Args, EFI_LBA);
       Start != EFI_LBA_LIST_TERMINATOR;
       Start = VA_ARG (Args, EFI_LBA)) {
    Length = VA_ARG (Args, UINTN);
  NumBytes = Length * BLOCK_SIZE;
  // FIXME first write then set the in memory buffer
  SetMem64 ((VOID *)Instance->MemBaseAddress + Start * BLOCK_SIZE, Length * BLOCK_SIZE, ~0UL);
  Base = (VOID *)Instance->MemBaseAddress + Start * BLOCK_SIZE;
  File = GetFileAndOffset (Base, &RelativeOffset);
  SendSvc (SP_SVC_RPMB_WRITE, File, (UINTN) Base, NumBytes, RelativeOffset);
  //DEBUG ((EFI_D_INFO, "%a Erase %lu LEN %lu Buf %p\n", __func__, Start, Length, Base));
  //OpTeeRpmbFvWrite(&Instance->FvbProtocol, Start , 0, &NumBytes, Base);
  }

  VA_END (Args);

  return EFI_SUCCESS;
}

/**
  Fixup internal data so that EFI can be call in virtual mode.
  Call the passed in Child Notify event and convert any pointers in
  lib to virtual mode.
  @param[in]    Event   The Event that is being processed
  @param[in]    Context Event Context
**/
VOID
EFIAPI
FvbVirtualNotifyEvent (
  IN EFI_EVENT        Event,
  IN VOID             *Context
  )
{
  EfiConvertPointer (0x0, (VOID**)&mFlashNvStorageBase);
  return;
}
#endif

STATIC
EFI_STATUS
EFIAPI
ValidateFvHeader (
  IN EFI_FIRMWARE_VOLUME_HEADER            *FwVolHeader
  )
{
  UINT16  Checksum;
  UINTN                       VariableStoreLength;
  VARIABLE_STORE_HEADER       *VariableStoreHeader;

  //
  // Verify the header revision, header signature, length
  // Length of FvBlock cannot be 2**64-1
  // HeaderLength cannot be an odd number
  //
  if ((FwVolHeader->Revision != EFI_FVH_REVISION) ||
      (FwVolHeader->Signature != EFI_FVH_SIGNATURE) ||
      (FwVolHeader->FvLength == ((UINT64) -1)) ||
      ((FwVolHeader->HeaderLength & 0x01) != 0)
      ) {
       DEBUG ((DEBUG_ERROR, "%a: No Firmware Volume header present\n",
      __FUNCTION__));
    return EFI_NOT_FOUND;
  }

  // Check the Firmware Volume Guid
  if ( CompareGuid (&FwVolHeader->FileSystemGuid, &gEfiSystemNvDataFvGuid) == FALSE ) {
    DEBUG ((DEBUG_ERROR, "%a: Firmware Volume Guid non-compatible\n",
      __FUNCTION__));
    return EFI_NOT_FOUND;
  }

   // Verify the header checksum
  Checksum = CalculateSum16((UINT16*)FwVolHeader, FwVolHeader->HeaderLength);
  if (Checksum != 0) {
    DEBUG ((DEBUG_ERROR, "%a: FV checksum is invalid (Checksum:0x%X)\n",
      __FUNCTION__, Checksum));
    return EFI_NOT_FOUND;
  }

    // Check the Variable Store Guid
  if (!CompareGuid (&VariableStoreHeader->Signature, &gEfiVariableGuid) &&
      !CompareGuid (&VariableStoreHeader->Signature, &gEfiAuthenticatedVariableGuid)) {
    DEBUG ((DEBUG_ERROR, "%a: Variable Store Guid non-compatible\n",
      __FUNCTION__));
    return EFI_NOT_FOUND;
  }

  VariableStoreLength = PcdGet32 (PcdFlashNvStorageVariableSize) - FwVolHeader->HeaderLength;
  if (VariableStoreHeader->Size != VariableStoreLength) {
    DEBUG ((DEBUG_ERROR, "%a: Variable Store Length does not match\n",
      __FUNCTION__));
    return EFI_NOT_FOUND;
  }

#if 0
  //
  // Verify the header checksum
  //
  HeaderLength  = (UINT16) (FwVolHeader->HeaderLength / 2);
  Ptr           = (UINT16 *) FwVolHeader;
  Checksum      = 0;
  while (HeaderLength > 0) {
    Checksum = *Ptr++;
    HeaderLength--;
  }

  if (Checksum != 0) {
    return EFI_NOT_FOUND;
  }
#endif
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
InitializeFvAndVariableStoreHeaders (
  EFI_PHYSICAL_ADDRESS Addr,
  UINTN BlockSize
  )
{
  EFI_STATUS                          Status = EFI_SUCCESS;
  VOID*                               Headers;
  UINTN                               HeadersLength;
  EFI_FIRMWARE_VOLUME_HEADER          *FirmwareVolumeHeader;
  VARIABLE_STORE_HEADER               *VariableStoreHeader;
  VOID *CP = (VOID*) Addr;
  DEBUG ((DEBUG_ERROR, "%a, %u Addr = %p\n", __FUNCTION__, __LINE__, CP));
  	
  HeadersLength = sizeof(EFI_FIRMWARE_VOLUME_HEADER) +
                  sizeof(EFI_FV_BLOCK_MAP_ENTRY) +
                  sizeof(VARIABLE_STORE_HEADER);
  Headers = AllocateZeroPool(HeadersLength);

  //
  // EFI_FIRMWARE_VOLUME_HEADER
  //
  FirmwareVolumeHeader = (EFI_FIRMWARE_VOLUME_HEADER*)Headers;
  CopyGuid (&FirmwareVolumeHeader->FileSystemGuid, &gEfiSystemNvDataFvGuid);
  FirmwareVolumeHeader->FvLength =
      FixedPcdGet32(PcdFlashNvStorageVariableSize) +
      FixedPcdGet32(PcdFlashNvStorageFtwWorkingSize) +
      FixedPcdGet32(PcdFlashNvStorageFtwSpareSize);
  FirmwareVolumeHeader->Signature = EFI_FVH_SIGNATURE;
  FirmwareVolumeHeader->Attributes = EFI_FVB2_READ_ENABLED_CAP |
                                     EFI_FVB2_READ_STATUS |
                                     EFI_FVB2_STICKY_WRITE |
                                     EFI_FVB2_MEMORY_MAPPED |
                                     EFI_FVB2_ERASE_POLARITY |
                                     EFI_FVB2_WRITE_STATUS |
                                     EFI_FVB2_WRITE_ENABLED_CAP;

  FirmwareVolumeHeader->HeaderLength = sizeof(EFI_FIRMWARE_VOLUME_HEADER) +
                                       sizeof(EFI_FV_BLOCK_MAP_ENTRY);
  FirmwareVolumeHeader->Revision = EFI_FVH_REVISION;
  FirmwareVolumeHeader->BlockMap[0].NumBlocks = NBLOCKS + 1;
  FirmwareVolumeHeader->BlockMap[0].Length      = BlockSize;
  FirmwareVolumeHeader->BlockMap[1].NumBlocks = 0;
  FirmwareVolumeHeader->BlockMap[1].Length      = 0;
  FirmwareVolumeHeader->Checksum = CalculateCheckSum16 (
                                     (UINT16*)FirmwareVolumeHeader,
                                     FirmwareVolumeHeader->HeaderLength);

  //
  // VARIABLE_STORE_HEADER
  //
  VariableStoreHeader = (VOID *)((UINTN)Headers +
                                 FirmwareVolumeHeader->HeaderLength);
  CopyGuid (&VariableStoreHeader->Signature, &gEfiAuthenticatedVariableGuid);
  VariableStoreHeader->Size = PcdGet32(PcdFlashNvStorageVariableSize) -
                              FirmwareVolumeHeader->HeaderLength;
  VariableStoreHeader->Format = VARIABLE_STORE_FORMATTED;
  VariableStoreHeader->State = VARIABLE_STORE_HEALTHY;

  // Install the combined super-header in memory
  CopyMem (CP, Headers, HeadersLength);
  DEBUG ((DEBUG_ERROR, " Headers = %p, HeadersLength = %u\n", (char *)Headers,
  			HeadersLength));
  hexdump("", (char*)Headers, HeadersLength);
#if 1
  Status = FvbWrite(&mInstance.FvbProtocol, 0, 0, &HeadersLength, Headers);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "FvbWrite failed\n"));
  }
#endif
//  SendSvc(SP_SVC_RPMB_WRITE, "EFI_VARS", (UINTN) Addr, HeadersLength, 0);

  FreePool (Headers);
  return Status;
}

EFI_STATUS
EFIAPI
FvbInitialize (
  EFI_PHYSICAL_ADDRESS  Addr
  )
{
  EFI_FIRMWARE_VOLUME_HEADER *FwVolHeader;
  EFI_STATUS                  Status = EFI_SUCCESS;
  UINT32                      FvbNumLba;

  //UINTN                       NumBytes;
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  // FirmwareVolumeHeader->FvLength is declared to have the Variable area
  // AND the FTW working area AND the FTW Spare contiguous.
  ASSERT (FixedPcdGet32 (PcdFlashNvStorageVariableBase) +
          FixedPcdGet32 (PcdFlashNvStorageVariableSize) ==
          FixedPcdGet32 (PcdFlashNvStorageFtwWorkingBase));
  ASSERT (FixedPcdGet32 (PcdFlashNvStorageFtwWorkingBase) +
          FixedPcdGet32 (PcdFlashNvStorageFtwWorkingSize) ==
          FixedPcdGet32 (PcdFlashNvStorageFtwSpareBase));

  // Check if the size of the area is at least one block size
  ASSERT ((FixedPcdGet32 (PcdFlashNvStorageVariableSize) > 0) &&
          (FixedPcdGet32 (PcdFlashNvStorageVariableSize) / BLOCK_SIZE > 0));
  ASSERT ((FixedPcdGet32 (PcdFlashNvStorageFtwWorkingSize) > 0) &&
          (FixedPcdGet32 (PcdFlashNvStorageFtwWorkingSize) / BLOCK_SIZE > 0));
  ASSERT ((FixedPcdGet32 (PcdFlashNvStorageFtwSpareSize) > 0) &&
          (FixedPcdGet32 (PcdFlashNvStorageFtwSpareSize) / BLOCK_SIZE > 0));

  // Ensure the Variable areas are aligned on block size boundaries
  ASSERT ((FixedPcdGet32 (PcdFlashNvStorageVariableBase) % BLOCK_SIZE) == 0);
  ASSERT ((FixedPcdGet32 (PcdFlashNvStorageFtwWorkingBase) % BLOCK_SIZE) == 0);
  ASSERT ((FixedPcdGet32 (PcdFlashNvStorageFtwSpareBase) % BLOCK_SIZE) == 0);
DEBUG ((DEBUG_ERROR, "Addr = %lx %a. %u\n", Addr, __FUNCTION__, __LINE__));
  // Read the file from disk and copy it to memory
  // FIXME Addr is probably not needed we can use mFlashNvStorageVariableBase
#if EEPROM_FUNC
  PreRead (Addr);
  DbgMem ("In flash data", Addr);
#endif
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *) Addr;
  Status = ValidateFvHeader(FwVolHeader);
  if (EFI_ERROR (Status)) {
    // There is no valid header, so time to install one.
    DEBUG ((DEBUG_INFO, "%a: The FVB Header is not valid.\n", __FUNCTION__));
    DEBUG ((DEBUG_INFO, "%a: Installing a correct one for this volume.\n",
      __FUNCTION__));

    // Erase all the NorFlash that is reserved for variable storage
    FvbNumLba = (PcdGet32(PcdFlashNvStorageVariableSize) +
                 PcdGet32(PcdFlashNvStorageFtwWorkingSize) +
                 PcdGet32(PcdFlashNvStorageFtwSpareSize)) /
                 BLOCK_SIZE;

    // Reset memory
    SetMem64 ((VOID *)Addr, NBLOCKS * BLOCK_SIZE, ~0UL);

    DbgMem ("In Memory data", Addr);
    // And erase the device
    // FIXME Check return status
    //SendSvc(SP_SVC_RPMB_WRITE, "EFI_VARS", (UINTN) Addr, 0x04000, 0);
    //SendSvc(SP_SVC_RPMB_WRITE, "FTW_WORK", (UINTN) Addr + 0x04000, 0x04000, 0);
    //SendSvc(SP_SVC_RPMB_WRITE, "FTW_SPARE", (UINTN) Addr + 0x08000, 0x04000, 0);
    // Install all appropriate headers
    Status = InitializeFvAndVariableStoreHeaders (Addr, BLOCK_SIZE);
    DbgMem ("Recovered data", Addr);
    if (EFI_ERROR (Status)) {
		DEBUG ((DEBUG_ERROR, "******** InitializeFvAndVariableStoreHeaders failed \n"));
		
      return Status;
    }
  } else {
    DEBUG ((DEBUG_INFO, "%a: Found valid FVB Header.\n", __FUNCTION__));
  }

  return Status;
}

EFI_STATUS
EepromFvbInitialize ()
{
  EFI_PHYSICAL_ADDRESS Addr = FixedPcdGet32 (PcdFlashNvStorageVariableBase);

  EFI_STATUS           Status;
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  /* Find a way to do this dynamically */
  Status = gMmst->MmAllocatePages (AllocateAddress, EfiRuntimeServicesData,
		                   NBLOCKS, &Addr);

  ASSERT_EFI_ERROR (Status);
  //Addr2 = AllocatePages(NBLOCKS);
  //ASSERT (Addr2 != NULL);
  //Addr = (EFI_PHYSICAL_ADDRESS) Addr2;
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  mInstance.MemBaseAddress = Addr;
  mInstance.BlockSize =      BLOCK_SIZE;
  mInstance.NBlocks =        NBLOCKS;
  mInstance.Signature =      FLASH_SIGNATURE;

  mInstance.FvbProtocol.GetAttributes = FvbGetAttributes;
  mInstance.FvbProtocol.SetAttributes = FvbSetAttributes;
  mInstance.FvbProtocol.GetPhysicalAddress = FvbGetPhysicalAddress;
  mInstance.FvbProtocol.GetBlockSize = FvbGetBlockSize;
  mInstance.FvbProtocol.Read = FvbRead;
  mInstance.FvbProtocol.Write = FvbWrite;
  mInstance.FvbProtocol.EraseBlocks = FvbEraseBlocks;
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  Status = FvbInitialize(Addr);
  ASSERT_EFI_ERROR (Status);
DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  Status = gMmst->MmInstallProtocolInterface (
                    &mInstance.Handle,
                    &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mInstance.FvbProtocol
                    );
  ASSERT_EFI_ERROR (Status);

#if 0
  //
  // Register for the virtual address change event
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  FvbVirtualNotifyEvent,
                  Context,
                  &gEfiEventVirtualAddressChangeGuid,
                  &mFvbVirtualAddrChangeEvent
                  );
  ASSERT_EFI_ERROR (Status);
#endif

  DEBUG ((EFI_D_INFO, "%a: Using NV store FV in-memory copy at 0x%lx\n",
    __FUNCTION__, Addr));

  return Status;
}

EFI_STATUS
EFIAPI
EepromInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                    Status;
  Status = EFI_SUCCESS;
#if EEPROM_FUNC

  UINT64       I2cClock;
  I2cBase = (EFI_PHYSICAL_ADDRESS)(FixedPcdGet64 (PcdI2c5BaseAddr));
//  + (PcdGet32 (PcdI2cBus) * FixedPcdGet32 (PcdI2cSize)));

  DEBUG ((DEBUG_ERROR, "%a I2cBase = %lx I2c5 Addr = %lx\n", __FUNCTION__,
    I2cBase, FixedPcdGet64 (PcdI2c5BaseAddr)));
  I2cClock = 87500000;
//  I2cClock = SocGetClock (IP_I2C, 0);
  if (I2cClock == 0) {
    DEBUG ((DEBUG_ERROR, "SocGetClock returned 0\n"));
  }

  DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  Status = I2cInitialize(FixedPcdGet64 (PcdI2c5BaseAddr), I2cClock, PcdGet32(PcdI2cSpeed));
  if (EFI_ERROR (Status)) {
    return Status;
  }
#endif
  DEBUG ((DEBUG_ERROR, "%a. %u\n", __FUNCTION__, __LINE__));
  Status = EepromFvbInitialize();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: EepromFVBInitialize() failed - %r\n",
      __FUNCTION__, Status));
    return Status;
  }

  DEBUG ((DEBUG_ERROR, "Status = %lx %a. %u\n", Status, __FUNCTION__, __LINE__));

  return Status;
}

