
#include <tee_internal_api.h>
#include "Enclave_t.h"


TEE_Result ecall_gp_open_session(uint32_t param_types,
                                 void *param,
                                 void **session)
{
   TEE_Param *param = (TEE_Param *)param;
   return TA_OpenSessionEntryPoint(param_types, param, session);
}

void ecall_gp_close_session(void *session);
{
    TA_CloseSessionEntryPoint(session);
}

TEE_Result ecall_gp_invoke(void *session, uint32_t cmd_id,
			               uint32_t param_types,
                           void *params)
{
    TEE_Param *param = (TEE_Param *)param;
    return TA_InvokeCommandEntryPoint(session, cmd_id,
                                      param_types, params)
}

// void OnInvoke()
// {
//     int cmd;
//     switch (cmd)
//     {
//         case OPEN_SESSION:
//             TA_OpenSessionEntryPoint();


//         case CLOSE_SESSION:
//             TA_CloseSessionEntryPoint();

//         case INVOKE_COMMAND:



//     }
// }