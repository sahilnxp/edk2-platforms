/** @file

  FV block I/O protocol driver for RPMB SPI flash exposed via OP-TEE

  Copyright (c) 2020, Linaro Ltd. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/ArmSvcLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>

#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/SmmFirmwareVolumeBlock.h>
#include <Guid/VariableFormat.h>

#include "OpTeeRpmbFv.h"

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



STATIC CONST MAP_VAL_TO_FILE Filenames[]= {
  CREATE_FILE_MAP(EFI_VARS),
  CREATE_FILE_MAP(FTW_WORK),
  CREATE_FILE_MAP(FTW_SPARE),
  { NULL, -1 }
};

STATIC
CHAR8* Map_To_String (
  CONST MAP_VAL_TO_FILE *Start,
  RPMB_FILE_MAP Map
 )
{
  while (Start) {
    if (Start->Map == Map) {
      return Start->Filename;
    }
    Start++;
  }

  return NULL;
}

STATIC
CHAR8* GetFileAndOffset (
  VOID* Mem,
  UINTN* Offset
  )
{
  RPMB_FILE_MAP Map = -1;
  UINTN Addr;

  // FIXME add proper limits and dont rely on a single 'else'
  // Use map MAP_VAL_TO_FILE and allow definition of Pcd derived filenames
  if ((UINTN) Mem < FixedPcdGet32 (PcdFlashNvStorageFtwWorkingBase) &&
    (UINTN) Mem >= FixedPcdGet32 (PcdFlashNvStorageVariableBase)) {
      Map = EFI_VARS;
      Addr = FixedPcdGet32 (PcdFlashNvStorageVariableBase);
    } else if ((UINTN) Mem < FixedPcdGet32 (PcdFlashNvStorageFtwSpareBase) &&
        (UINTN) Mem >= FixedPcdGet32 (PcdFlashNvStorageFtwWorkingBase)) {
      Map =  FTW_WORK;
      Addr = FixedPcdGet32 (PcdFlashNvStorageFtwWorkingBase);
    } else if ((UINTN) Mem < FixedPcdGet32 (PcdFlashNvStorageFtwSpareBase) +
	FixedPcdGet32(PcdFlashNvStorageFtwSpareSize) &&
        (UINTN) Mem >= FixedPcdGet32 (PcdFlashNvStorageFtwSpareBase)) {
      Map = FTW_SPARE;
      Addr = FixedPcdGet32 (PcdFlashNvStorageFtwSpareBase);
    } else {
       //FIXME this will assert string is NULL
	DEBUG ((DEBUG_INFO, "################## WILL ASSERT\n"));
    }
    *Offset = (UINTN) Mem - Addr;

  return Map_To_String(Filenames, Map);
}
/**
  The SendSvc() function sends an svc call to OP-TEE

  @param Act       Stored in regs->x0

  @param Attributes Pointer to EFI_FVB_ATTRIBUTES_2 in which the
                    attributes and current settings are
                    returned. Type EFI_FVB_ATTRIBUTES_2 is defined
                    in EFI_FIRMWARE_VOLUME_HEADER.

  @retval EFI_SUCCESS The firmware volume attributes were
                      returned.

**/

STATIC
UINTN
SendSvc (
  UINTN  SvcAct,
  CHAR8  *File,
  UINTN  Addr,
  UINTN  NumBytes,
  UINTN  Offset
  )
{
  ARM_SVC_ARGS  SvcArgs;

  ZeroMem (&SvcArgs, sizeof (ARM_SVC_ARGS));

#if 0
  char *buff = (char *)Addr+Offset;
  switch (SvcAct) {
  case SP_SVC_RPMB_READ:
	//if (!AsciiStrCmp(File, "FWP_WORK")
		//DEBUG ((EFI_D_INFO, "%a: SENDING READ FOR %a addr: 0x%08x %lx\n", __func__, File, Addr, Offset));
    break;
  case SP_SVC_RPMB_WRITE:
		DEBUG ((EFI_D_INFO, "%a: SENDING WRITE FOR %a addr: 0x%08x LEN:%lu OFFSET: %lu\n", __func__, File, Addr, NumBytes, Offset));
		hexdump("", buff, 0x40);
    break;
  }
#endif

  SvcArgs.Arg0 = SvcAct;
  SvcArgs.Arg1 = (UINTN) File;
  SvcArgs.Arg2 = AsciiStrLen(File);
  SvcArgs.Arg3 = Addr;
  SvcArgs.Arg4 = NumBytes;
  SvcArgs.Arg5 = Offset;
  ArmCallSvc (&SvcArgs);

  DEBUG ((EFI_D_INFO, "%a: SVC Call ret 0x%x\n", __func__, SvcArgs.Arg0));

  return SvcArgs.Arg0;
}

/**
  The GetAttributes() function retrieves the attributes and
  current settings of the block.

  @param This       Indicates the EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL instance.

  @param Attributes Pointer to EFI_FVB_ATTRIBUTES_2 in which the
                    attributes and current settings are
                    returned. Type EFI_FVB_ATTRIBUTES_2 is defined
                    in EFI_FIRMWARE_VOLUME_HEADER.

  @retval EFI_SUCCESS The firmware volume attributes were
                      returned.

**/
STATIC
EFI_STATUS
OpTeeRpmbFvGetAttributes (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  OUT       EFI_FVB_ATTRIBUTES_2                *Attributes
  )
{
  *Attributes = EFI_FVB2_READ_ENABLED_CAP   | // Reads may be enabled
                EFI_FVB2_READ_STATUS        | // Reads are currently enabled
                EFI_FVB2_WRITE_STATUS       | // Writes are currently enabled
                EFI_FVB2_WRITE_ENABLED_CAP  | // Writes may be enabled
                EFI_FVB2_STICKY_WRITE       | // A block erase is required to flip bits into EFI_FVB2_ERASE_POLARITY
                EFI_FVB2_MEMORY_MAPPED      | // It is memory mapped
                EFI_FVB2_ERASE_POLARITY;      // After erasure all bits take this value (i.e. '1')

  return EFI_SUCCESS;
}

/**
  The SetAttributes() function sets configurable firmware volume
  attributes and returns the new settings of the firmware volume.

  @param This         Indicates the EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL instance.

  @param Attributes   On input, Attributes is a pointer to
                      EFI_FVB_ATTRIBUTES_2 that contains the
                      desired firmware volume settings. On
                      successful return, it contains the new
                      settings of the firmware volume. Type
                      EFI_FVB_ATTRIBUTES_2 is defined in
                      EFI_FIRMWARE_VOLUME_HEADER.

  @retval EFI_SUCCESS           The firmware volume attributes were returned.

  @retval EFI_INVALID_PARAMETER The attributes requested are in
                                conflict with the capabilities
                                as declared in the firmware
                                volume header.

**/
STATIC
EFI_STATUS
OpTeeRpmbFvSetAttributes (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  IN OUT    EFI_FVB_ATTRIBUTES_2                *Attributes
  )
{
  return EFI_SUCCESS;  // ignore for now
}

/**
  The GetPhysicalAddress() function retrieves the base address of
  a memory-mapped firmware volume. This function should be called
  only for memory-mapped firmware volumes.

  @param This     Indicates the EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL instance.

  @param Address  Pointer to a caller-allocated
                  EFI_PHYSICAL_ADDRESS that, on successful
                  return from GetPhysicalAddress(), contains the
                  base address of the firmware volume.

  @retval EFI_SUCCESS       The firmware volume base address was returned.

  @retval EFI_UNSUPPORTED   The firmware volume is not memory mapped.

**/
STATIC
EFI_STATUS
OpTeeRpmbFvGetPhysicalAddress (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  OUT       EFI_PHYSICAL_ADDRESS                *Address
  )
{
  MEM_INSTANCE *Instance;

  Instance = INSTANCE_FROM_FVB_THIS(This);
  *Address = Instance->MemBaseAddress;

  return EFI_SUCCESS;
}

/**
  The GetBlockSize() function retrieves the size of the requested
  block. It also returns the number of additional blocks with
  the identical size. The GetBlockSize() function is used to
  retrieve the block map (see EFI_FIRMWARE_VOLUME_HEADER).


  @param This           Indicates the EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL instance.

  @param Lba            Indicates the block for which to return the size.

  @param BlockSize      Pointer to a caller-allocated UINTN in which
                        the size of the block is returned.

  @param NumberOfBlocks Pointer to a caller-allocated UINTN in
                        which the number of consecutive blocks,
                        starting with Lba, is returned. All
                        blocks in this range have a size of
                        BlockSize.


  @retval EFI_SUCCESS             The firmware volume base address was returned.

  @retval EFI_INVALID_PARAMETER   The requested LBA is out of range.

**/
STATIC
EFI_STATUS
OpTeeRpmbFvGetBlockSize (
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
STATIC
VOID
PreRead (
  EFI_PHYSICAL_ADDRESS Addr
 )
{
  // FIXME  Clean this up with proper definitions and remove the hardcoded
  // filenames
  EFI_PHYSICAL_ADDRESS NewAddr = Addr;
  UINTN Size = FixedPcdGet32(PcdFlashNvStorageVariableSize); // FIXME add size for all
  SendSvc(SP_SVC_RPMB_READ, "EFI_VARS", (UINTN) NewAddr, Size, 0);
  SendSvc(SP_SVC_RPMB_READ, "FTW_WORK", (UINTN) NewAddr + Size, Size, 0);
  SendSvc(SP_SVC_RPMB_READ, "FTW_SPARE", (UINTN) NewAddr + 2 * Size, Size, 0);
}

STATIC
EFI_STATUS
OpTeeRpmbFvRead (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  IN        EFI_LBA                             Lba,
  IN        UINTN                               Offset,
  IN OUT    UINTN                               *NumBytes,
  IN OUT    UINT8                               *Buffer
  )
{
  EFI_STATUS   Status = EFI_SUCCESS;
  MEM_INSTANCE *Instance;
  VOID         *Base;
  //CHAR8        *File;
  //UINTN         Addr;
  /*
   * OP-TEE uses a FAT filesystem on the RPMB accesses, and stores data in 3
   * different files. We need to calculate the relative per file offset
   */
  //UINTN         RelativeOffset;

  Instance = INSTANCE_FROM_FVB_THIS(This);

  Base = (VOID *)Instance->MemBaseAddress + Lba * BLOCK_SIZE + Offset;
  // Update the memory copy
  CopyMem (Buffer, Base, *NumBytes);

#if 0
  // FIXME read the actual hardware and compare memory
  File = GetFileAndOffset (Base, &RelativeOffset);
  SendSvc (SP_SVC_RPMB_READ, File, Addr, *NumBytes, RelativeOffset);
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

  @param This     Indicates the EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL instance.

  @param Lba      The starting logical block index to write to.

  @param Offset   Offset into the block at which to begin writing.

  @param NumBytes The pointer to a UINTN. At entry, *NumBytes
                  contains the total size of the buffer. At
                  exit, *NumBytes contains the total number of
                  bytes actually written.

  @param Buffer   The pointer to a caller-allocated buffer that
                  contains the source for the write.

  @retval EFI_SUCCESS         The firmware volume was written successfully.

  @retval EFI_BAD_BUFFER_SIZE The write was attempted across an
                              LBA boundary. On output, NumBytes
                              contains the total number of bytes
                              actually written.

  @retval EFI_ACCESS_DENIED   The firmware volume is in the
                              WriteDisabled state.

  @retval EFI_DEVICE_ERROR    The block device is malfunctioning
                              and could not be written.


**/
STATIC
EFI_STATUS
OpTeeRpmbFvWrite (
  IN CONST  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  IN        EFI_LBA                             Lba,
  IN        UINTN                               Offset,
  IN OUT    UINTN                               *NumBytes,
  IN        UINT8                               *Buffer
  )
{
  MEM_INSTANCE *Instance;
  EFI_STATUS   Status = EFI_SUCCESS;
  VOID         *Base;
  CHAR8        *File;
  /*
   * OP-TEE uses a FAT filesystem on the RPMB accesses, and stores data in 3
   * different files. We need to calculate the relative per file offset
   */
  UINTN         RelativeOffset;

  Instance = INSTANCE_FROM_FVB_THIS(This);
  Base = (VOID *)Instance->MemBaseAddress + Lba * BLOCK_SIZE + Offset;
  File = GetFileAndOffset (Base, &RelativeOffset);

  // FIXME make op-tee report write failures on a register and abort the in-memory update
  // if writing the RPMB fails + return the correct status
  // Update the memory copy
  CopyMem (Base, Buffer, *NumBytes);
  // FIXME swap it over memcpy and s/Base/Buffer after dve is done
  SendSvc (SP_SVC_RPMB_WRITE, File, (UINTN) Base, *NumBytes, RelativeOffset);

  return Status;
}

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
OpTeeRpmbFvErase (
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


STATIC
EFI_STATUS
EFIAPI
ValidateFvHeader (
  IN EFI_FIRMWARE_VOLUME_HEADER            *FwVolHeader
  )
{
  UINT16  *Ptr;
  UINT16  HeaderLength;
  UINT16  Checksum;

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
    return EFI_NOT_FOUND;
  }

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
  //FIXME Get filename and address dynamically GetFileOffset
  SendSvc(SP_SVC_RPMB_WRITE, "EFI_VARS", (UINTN) Addr, HeadersLength, 0);

  FreePool (Headers);
  return Status;
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
  hexdump("", (char*)NewAddr+Size, 0x80);
  DEBUG ((DEBUG_INFO, "%a: %a FTW_SPARE:\n", __FUNCTION__, Prefix));
  hexdump("", (char*)NewAddr+2*Size, 0x80);
}

STATIC
EFI_STATUS
EFIAPI
FvbInitialize (
  EFI_PHYSICAL_ADDRESS  Addr
  )
{
  EFI_FIRMWARE_VOLUME_HEADER *FwVolHeader;
  EFI_STATUS                  Status;
  UINT32                      FvbNumLba;
  UINTN                       mFlashNvStorageVariableBase;
  //UINTN                       NumBytes;

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

  mFlashNvStorageVariableBase = FixedPcdGet32 (PcdFlashNvStorageVariableBase);
  // Read the file from disk and copy it to memory
  // FIXME Addr is probably not needed we can use mFlashNvStorageVariableBase
  PreRead (Addr);
  DbgMem ("In flash data", Addr);

  FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *) mFlashNvStorageVariableBase;
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
      return Status;
    }
  } else {
    DEBUG ((DEBUG_INFO, "%a: Found valid FVB Header.\n", __FUNCTION__));
  }

  return Status;
}

EFI_STATUS
EFIAPI
OpTeeRpmbFvInit (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  //VOID          *Addr2;
  EFI_PHYSICAL_ADDRESS Addr = FixedPcdGet32 (PcdFlashNvStorageVariableBase);
  EFI_STATUS           Status;

  /* Find a way to do this dynamically */
  Status = gMmst->MmAllocatePages (AllocateAddress, EfiRuntimeServicesData,
		                   NBLOCKS, &Addr);
  ASSERT_EFI_ERROR (Status);
  //Addr2 = AllocatePages(NBLOCKS);
  //ASSERT (Addr2 != NULL);
  //Addr = (EFI_PHYSICAL_ADDRESS) Addr2;

  mInstance.MemBaseAddress = Addr;
  mInstance.BlockSize =      BLOCK_SIZE;
  mInstance.NBlocks =        NBLOCKS;
  mInstance.Signature =      FLASH_SIGNATURE;
  mInstance.FvbProtocol.GetAttributes =   OpTeeRpmbFvGetAttributes;
  mInstance.FvbProtocol.SetAttributes =   OpTeeRpmbFvSetAttributes;
  mInstance.FvbProtocol.GetPhysicalAddress =  OpTeeRpmbFvGetPhysicalAddress;
  mInstance.FvbProtocol.GetBlockSize =    OpTeeRpmbFvGetBlockSize;
  mInstance.FvbProtocol.Read =          OpTeeRpmbFvRead;
  mInstance.FvbProtocol.Write =         OpTeeRpmbFvWrite;
  mInstance.FvbProtocol.EraseBlocks =     OpTeeRpmbFvErase;

  Status = FvbInitialize(Addr);
  ASSERT_EFI_ERROR (Status);

  Status = gMmst->MmInstallProtocolInterface (
                    &mInstance.Handle,
                    &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mInstance.FvbProtocol
                    );
  ASSERT_EFI_ERROR (Status);

  DEBUG ((EFI_D_INFO, "%a: Register OP-TEE RPMB Fvb\n", __FUNCTION__));
  DEBUG ((EFI_D_INFO, "%a: Using NV store FV in-memory copy at 0x%lx\n",
    __FUNCTION__, Addr));

  return Status;
}
