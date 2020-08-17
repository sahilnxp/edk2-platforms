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
#include <IndustryStandard/ArmFfaSvc.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PcdLib.h>

#define SP_SVC_GET_I2C_ADDR             0xC4000068

static const UINT16 peripheral_mgr_id = 5U;
STATIC
UINTN
GetI2CAddress (
  UINT64  *Address
  )
{
  ARM_SVC_ARGS  SvcArgs;

  ZeroMem (&SvcArgs, sizeof (SvcArgs));

  SvcArgs.Arg0 = ARM_SVC_ID_FFA_MSG_SEND_DIRECT_REQ_AARCH64;
  SvcArgs.Arg1 = peripheral_mgr_id;
  SvcArgs.Arg2 = 0; //FIXME??
  SvcArgs.Arg3 = SP_SVC_GET_I2C_ADDR;

  ArmCallSvc (&SvcArgs);
  if (SvcArgs.Arg3) {
    DEBUG ((DEBUG_ERROR, "%a: Svc Call 0x%08x failed with 0x%x\n",
     __func__, SP_SVC_GET_I2C_ADDR, SvcArgs.Arg3));
  }

  *Address = SvcArgs.Arg4;
  return SvcArgs.Arg3;
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
