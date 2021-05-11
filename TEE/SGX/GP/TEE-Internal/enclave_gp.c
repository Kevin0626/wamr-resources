
#include <tee_internal_api.h>
#include "Enclave_t.h"


TEE_Result ecall_gp_open_session(uint32_t param_types,
                                 void *params,
                                 void **session)
{
   return TA_OpenSessionEntryPoint(param_types, (TEE_Param *)params, session);
}

void ecall_gp_close_session(void *session)
{
    TA_CloseSessionEntryPoint(session);
}

TEE_Result ecall_gp_invoke(void *session, uint32_t cmd_id,
			               uint32_t param_types,
                           void *params)
{
    return TA_InvokeCommandEntryPoint(session, cmd_id,
                                      param_types, (TEE_Param *)params);
}