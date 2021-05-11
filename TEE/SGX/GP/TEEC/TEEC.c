#include "tee_client_api.h"
#include "Enclave_u.h"

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	return TEEC_SUCCESS;
}


void TEEC_FinalizeContext(TEEC_Context *context)
{

}


TEEC_Result TEEC_OpenSession(TEEC_Context *context,
			     TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connectionMethod,
			     const void *connectionData,
			     TEEC_Operation *operation,
			     uint32_t *returnOrigin)
{
	return ecall_gp_open_session(operation->paramTypes, operation->params, (void **)session);
}


void TEEC_CloseSession(TEEC_Session *session)
{
	ecall_gp_close_session(session);
}


TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
			       uint32_t commandID,
			       TEEC_Operation *operation,
			       uint32_t *returnOrigin)
{
    return ecall_gp_invoke(session, commandID, operation->paramTypes, operation->params);
}
