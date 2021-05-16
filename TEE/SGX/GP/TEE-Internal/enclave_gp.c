
#include <tee_internal_api.h>
#include "cup_sgx_enclave_t.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define INVALID_GP_SESSION_ID 0
#define MAX_SESSIONS 10

#define TEE_ERROR_MAX_SESSION -100
#define TEE_ERROR_INVALID_SESSION -101

typedef struct 
{
    uint32_t session_id;
    void* user_data;
    bool used;
} gp_tee_session_t;

gp_tee_session_t g_tee_sessions[MAX_SESSIONS] = {0};

gp_tee_session_t * allocate_session()
{
    static uint32_t session_id_mark = 1;
    for(int i=0; i< MAX_SESSIONS; i++)
    {
        if(!g_tee_sessions[i].used)
        {
            memset(&g_tee_sessions[i], 0, sizeof(g_tee_sessions[i]));
            g_tee_sessions[i].used = true;
            g_tee_sessions[i].session_id = session_id_mark++;
            if(session_id_mark == INVALID_GP_SESSION_ID)
                session_id_mark = 1;
            return &g_tee_sessions[i];
        }
    }

    return NULL;
}

int get_session_num()
{
    int cnt = 0;
    for(int i=0; i< MAX_SESSIONS; i++)
    {
        if(g_tee_sessions[i].used)
        {
            cnt ++;;
        }
    }

    return cnt;
}

gp_tee_session_t * lookup_session(uint32_t session_id)
{
    for(int i=0; i< MAX_SESSIONS; i++)
    {
        if(g_tee_sessions[i].used && g_tee_sessions[i].session_id == session_id)
        {
            return &g_tee_sessions[i];
        }
    }

    return NULL;
}

void free_session(gp_tee_session_t * session)
{
    for(int i=0; i< MAX_SESSIONS; i++)
    {
        if(&g_tee_sessions[i] == session)
        {
            memset(&g_tee_sessions[i], 0, sizeof(g_tee_sessions[i]));
            return;
        }
    }
}

static bool create_entry_called = false;


TEE_Result ecall_gp_open_session(uint32_t param_types,
                                 void *params,
                                 uint32_t *session_id)
{
    TEE_Result ret;
    gp_tee_session_t * session = allocate_session();
    if(session == NULL)
        return TEE_ERROR_MAX_SESSION;

    if(!create_entry_called)
    {
        ret = TA_CreateEntryPoint();
        if(ret != TEE_SUCCESS)
        {
            free_session(session);
            *session_id = INVALID_GP_SESSION_ID;
            ocall_print("TA_CreateEntryPoint returned fail.\n");
            return ret;
        }
        ocall_print("TA_CreateEntryPoint executed.\n");
        create_entry_called = true;
    }


    ret = TA_OpenSessionEntryPoint(param_types, (TEE_Param *)params, &session->user_data);

    if(ret != TEE_SUCCESS)
    {
        free_session(session);
        *session_id = INVALID_GP_SESSION_ID;
    }
    else
    {
        ocall_print("Open TA session successfully!\n");
        *session_id = session->session_id;
        ocall_print("Get session_id: ");
        ocall_print_int(*session_id);
        ocall_print("\n\n====================================\n\n");
    }
    return ret;
}

void ecall_gp_close_session(uint32_t session_id)
{

    gp_tee_session_t * session = lookup_session(session_id);
    if(session == NULL)
    {
        return;
    }
    ocall_print("\n====================================\n");

    TA_CloseSessionEntryPoint(session->user_data);
    ocall_print("Close TA session successfully!\n");
    free_session(session);

    if(lookup_session(session_id) == NULL)
    {
        ocall_print("Session has been free!\n");
    }

    if(get_session_num() == 0 && create_entry_called)
    {
        TA_DestroyEntryPoint();
        create_entry_called = false;
        ocall_print("TA_DestroyEntryPoint executed.\n");
    }

    ocall_print("\n====================================\n\n");
}

TEE_Result ecall_gp_invoke(uint32_t session_id, uint32_t cmd_id,
			               uint32_t param_types,
                           void *params)
{
    gp_tee_session_t * session = lookup_session(session_id);
    if(session == NULL)
    {
        return TEE_ERROR_INVALID_SESSION;
    }

    return TA_InvokeCommandEntryPoint(session->user_data, cmd_id,
                                      param_types, (TEE_Param *)params);
}