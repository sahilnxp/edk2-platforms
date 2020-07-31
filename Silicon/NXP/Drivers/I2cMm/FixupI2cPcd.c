/** @file

  Update the patched PCDs to their correct value

  Copyright (c) 2020, Linaro Ltd. All rights reserved.
  Copyright 2020 NXP.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/**
 * Patch the relevant PCDs of the RPMB driver with the correct address of the
 * allocated memory
 *
**/
#include <Library/ArmSvcLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PcdLib.h>

#define SP_SVC_GET_I2C_ADDR             0xC4000068

STATIC
UINTN
GetI2CAddress (
  UINT64  *Address
  )
{
  ARM_SVC_ARGS  SvcArgs;

  ZeroMem (&SvcArgs, sizeof (ARM_SVC_ARGS));

  SvcArgs.Arg0 = SP_SVC_GET_I2C_ADDR;
  SvcArgs.Arg1 = 0;
  ArmCallSvc (&SvcArgs);

  DEBUG ((EFI_D_INFO, "%a: SVC Call ret 0x%x, 0x%lx\n", __func__,
    SvcArgs.Arg0, SvcArgs.Arg1));

  *Address = SvcArgs.Arg1;
  return SvcArgs.Arg0;
}

EFI_STATUS
EFIAPI
FixI2cPcd (
  VOID
  )
{
  EFI_STATUS  Status = EFI_SUCCESS;
  UINT64      I2cBaseAddr;

  // Get the I2C BaseAddress from OP-TEE
  if (GetI2CAddress(&I2cBaseAddr))
    Status = EFI_DEVICE_ERROR;

  // Set the updated PCDs
  PatchPcdSet64 (PcdI2c5BaseAddr, I2cBaseAddr);

  DEBUG ((DEBUG_INFO, "%a: Fixup PcdI2c5BaseAddr: 0x%lx\n",
    __FUNCTION__, PcdGet64 (PcdI2c5BaseAddr)));

  return Status;
}
