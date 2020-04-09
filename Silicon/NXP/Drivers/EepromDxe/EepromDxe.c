/*++ @file  EepromDxe.c

 Copyright (c) 2011 - 2014, ARM Ltd. All rights reserved.<BR>
 Copyright 2017-2020 NXP

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
#include <Guid/NvVarStoreFormatted.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/MmServicesTableLib.h>
#include <Protocol/I2cMaster.h>

#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/SmmFirmwareVolumeBlock.h>
#include <Guid/VariableFormat.h>


STATIC EFI_I2C_MASTER_PROTOCOL    *mI2cMaster = NULL;
STATIC EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL    eepromFvb;

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
  I2C_REG_REQUEST         RequestPacket;
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

  Status = mI2cMaster->StartRequest(mI2cMaster, SlaveAddress, 
             (EFI_I2C_REQUEST_PACKET *)&RequestPacket, NULL, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "I2C StartRequest Failed while Writing data\n"));
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
  OUT UINT8   *RegValue,
  IN  UINT32  RegValueNumBytes
  )
{
  EFI_I2C_OPERATION       *Operations;
  I2C_REG_REQUEST         RequestPacket;
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
  Operations[OperationCount].Flags = I2C_FLAG_READ;
  OperationCount++;

  RequestPacket.OperationCount = OperationCount;

  Status = mI2cMaster->StartRequest(mI2cMaster, SlaveAddress, 
             (EFI_I2C_REQUEST_PACKET *)&RequestPacket, NULL, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "I2C StartRequest Failed while reading data\n"));
    return Status;
  }

  return Status;
}

EFI_STATUS
EFIAPI
EepromDxeInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                    Status;
  UINTN                         BusFrequency;
  EFI_I2C_MASTER_PROTOCOL       *I2cMaster;
  EFI_HANDLE                    Handle;
  

  Status = gBS->LocateProtocol (&gEfiI2cMasterProtocolGuid, NULL,
			(VOID **)&I2cMaster);

  ASSERT_EFI_ERROR (Status);

  Status = I2cMaster->Reset (I2cMaster);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: I2CMaster->Reset () failed - %r\n",
      __FUNCTION__, Status));
    return Status;
  }

  BusFrequency = FixedPcdGet32 (PcdI2cSpeed);
  Status = I2cMaster->SetBusFrequency (I2cMaster, &BusFrequency);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: I2CMaster->SetBusFrequency () failed - %r\n",
      __FUNCTION__, Status));
    return Status;
  }

  mI2cMaster = I2cMaster;

  Status = EepromFvbInitialize(&eepromFvb);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: EepromFVBInitialize() failed - %r\n",
      __FUNCTION__, Status));
    return Status;
  }
 
  Status = gMmst->MmInstallProtocolInterface (
                    &Handle,
                    &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &eepromFvb
                    );
  ASSERT_EFI_ERROR (Status);

  DEBUG ((EFI_D_INFO, "%a: Using NV store FV in-memory copy at 0x%lx\n",
    __FUNCTION__, Addr));

  return Status;
}
}
