#include "tee_client_api.h"
#include <unistd.h>
#include <pwd.h>
#include "sgx_urts.h"
#include "sgx_error.h"
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#if !defined(SGX_GP_ENCLAVE_HEADER)
#include "cup_sgx_enclave_u.h"
#else
#include SGX_GP_ENCLAVE_HEADER
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TOKEN_FILENAME   "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define MAX_PATH 1024

static sgx_enclave_id_t g_eid = 0;

void
ocall_print(const char* str)
{
    printf("%s", str);
}

void
ocall_print_int(uint32_t val)
{
    printf("%d", val);
}

static char *
get_exe_path(char *path_buf, unsigned path_buf_size)
{
    ssize_t i;
    ssize_t size = readlink("/proc/self/exe",
                            path_buf, path_buf_size - 1);

    if (size < 0 || (size >= path_buf_size - 1)) {
        return NULL;
    }

    path_buf[size] = '\0';
    for (i = size - 1; i >= 0; i--) {
        if (path_buf[i] == '/') {
            path_buf[i + 1] = '\0';
            break;
        }
    }
    return path_buf;
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
static int
enclave_init(sgx_enclave_id_t *p_eid)
{
    char token_path[MAX_PATH] = { '\0' };
    char enclave_path[MAX_PATH] = { '\0' };
    const char *home_dir;
    sgx_launch_token_t token = { 0 };
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    size_t write_num, enc_file_len;
    FILE *fp;

    enc_file_len = strlen(ENCLAVE_FILENAME);
    if (!get_exe_path(enclave_path, sizeof(enclave_path) - enc_file_len)) {
        printf("Failed to get exec path\n");
        return -1;
    }
    memcpy(enclave_path + strlen(enclave_path), ENCLAVE_FILENAME, enc_file_len);

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    }
    else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n",
               token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG,
                             &token, &updated, p_eid, NULL);
    if (ret != SGX_SUCCESS)
        /* Try to load enclave.sign.so from the path of exe file */
        ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG,
                                 &token, &updated, p_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave from %s, error code: %d\n",
               ENCLAVE_FILENAME, ret);
        if (fp != NULL)
            fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL)
        return 0;

    write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);

    fclose(fp);
    return 0;
}

int Enclave_Initialize()
{
	return enclave_init(&g_eid);
}

void Enclave_Destory()
{
	sgx_destroy_enclave(g_eid);
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
    memset(context, 0, sizeof(*context));

	/* Initialize the enclave */
	if (Enclave_Initialize() < 0) {
		printf("Fail to initialize enclave.");
        return -1;
    }

    context->fd = g_eid;

	return TEEC_SUCCESS;
}


void TEEC_FinalizeContext(TEEC_Context *context)
{
    Enclave_Destory();
    memset(context, 0, sizeof(*context));
}

typedef union {
	struct {
		void *buffer;
		uint32_t size;
	} memref;
	struct {
		uint32_t a;
		uint32_t b;
	} value;
} SGX_TEE_Param;

bool ToSGX_TEE_Param(TEEC_Operation *operation, SGX_TEE_Param * p)
{
    for(int i=0;i<TEEC_CONFIG_PAYLOAD_REF_COUNT;i++)
    {
        uint8_t t = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);
        switch (t)
        {
        case TEEC_NONE:
            /* code */
            break;
        case TEEC_VALUE_INPUT:
        case TEEC_VALUE_INOUT:
        case TEEC_VALUE_OUTPUT:
            p[i].value.a = operation->params[i].value.a;
            p[i].value.b = operation->params[i].value.b;
            break;
        case TEEC_MEMREF_TEMP_INPUT:
        case TEEC_MEMREF_TEMP_INOUT:
        case TEEC_MEMREF_TEMP_OUTPUT: 
            p[i].memref.buffer = operation->params[i].tmpref.buffer;
            p[i].memref.size = operation->params[i].tmpref.size;
            break;
        default:
            printf ("%s: TEE para type %d not supported\n", __FUNCTION__, t);
            return false;
        }
    }

    return true;
}

bool FromSGX_TEE_Param(TEEC_Operation *operation, SGX_TEE_Param * p)
{
    for(int i=0;i<TEEC_CONFIG_PAYLOAD_REF_COUNT;i++)
    {
        uint8_t t = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);
        switch (t)
        {
        case TEEC_NONE:
            /* code */
            break;
        case TEEC_VALUE_OUTPUT:
        case TEEC_VALUE_INOUT:
        case TEEC_VALUE_INPUT:
            operation->params[i].value.a = p[i].value.a;
            operation->params[i].value.b = p[i].value.b;
            break;
        case TEEC_MEMREF_TEMP_OUTPUT:
        case TEEC_MEMREF_TEMP_INOUT:
        case TEEC_MEMREF_TEMP_INPUT: 
            operation->params[i].tmpref.buffer = p[i].memref.buffer;
            operation->params[i].tmpref.size = p[i].memref.size;
            break;

        default:
            printf ("%s: TEE para type %d not supported\n", __FUNCTION__, t);
            return false;
        }
    }

    return true;
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context,
			     TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connectionMethod,
			     const void *connectionData,
			     TEEC_Operation *operation,
			     uint32_t *returnOrigin)
{
	TEEC_Result ret;
    int sgx_status;
    SGX_TEE_Param sgx_params[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {0};
    if(!ToSGX_TEE_Param(operation, sgx_params))
    {
        printf("TEEC_OpenSession: unsupported in paramers type\n");
        return -1;
    }
    sgx_status = ecall_gp_open_session(g_eid, &ret, operation->paramTypes,
	                          sgx_params, &session->session_id);
    if (sgx_status != SGX_SUCCESS) {
        printf("TEEC_OpenSession: ecall_gp_open_session return %d\n", sgx_status);
		return -1;
	}

    if(!FromSGX_TEE_Param(operation, sgx_params))
    {
        printf("TEEC_OpenSession: unsupported out paramers type\n");
        return -1;
    }
    session->ctx = context;

	return ret;
}


void TEEC_CloseSession(TEEC_Session *session)
{
	ecall_gp_close_session(g_eid, session->session_id);
    memset(session, 0, sizeof(*session));
}


TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
			       uint32_t commandID,
			       TEEC_Operation *operation,
			       uint32_t *returnOrigin)
{
	TEEC_Result ret;
    SGX_TEE_Param sgx_params[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {0};
    if(!ToSGX_TEE_Param(operation, sgx_params))
    {
        printf("TEEC_InvokeCommand: unsupported in paramers type\n");
        return -1;
    }

    if(ecall_gp_invoke(g_eid, &ret, session->session_id, commandID,
					          operation->paramTypes, sgx_params) != SGX_SUCCESS) {
		return -1;
	}
    if(!FromSGX_TEE_Param(operation, sgx_params))
    {
        printf("TEEC_InvokeCommand: unsupported out paramers type\n");
        return -1;
    }
	return ret;
}



static int load_file_to_memory(const char *filename, char **result)
{
    size_t size = 0;
    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        printf("load_file_to_memory: open fail. error: %d, file: %s", errno, filename);
        *result = NULL;
        return -1; // -1 means file opening fail
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *result = (char *)malloc(size+1);
    if (size != fread(*result, sizeof(char), size, f))
    {
        printf("load_file_to_memory: read fail. error: %d, file: %s", errno, filename);
        free(*result);
        return -2; // -2 means file reading fail
    }
    fclose(f);
    (*result)[size] = 0;
    return (int)size;
}



#define INSTALL_TA 101
#define TA_CUP_BTA_UUID \
	{ 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

TEEC_Result TEECX_Open_wasmTA_session(TEEC_Context * ctx,
	TEEC_Session *sess ,
    const char * sp, const char * ta_name, const char * wasmTA_path)
{
	TEEC_Result res;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_CUP_BTA_UUID;
	uint32_t err_origin;
    char * content = NULL;

    int len = 0;
    if(wasmTA_path)
    {
        len= load_file_to_memory(wasmTA_path, &content);
        if(len <= 0)
        {
            printf("%s: load wasm binary [%s] fail. err: %d\n", 
                __FUNCTION__, wasmTA_path, errno);
            return -1;
        }
    }
    else
    {
            printf("%s: no wasm TA path given, hope it is alredy in the SGX enclave\n", 
                __FUNCTION__);
    }

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	memset(&op, 0, sizeof(op));
    op.params[0].value.a = INSTALL_TA;
    op.params[1].tmpref.buffer = (void*)ta_name;
    op.params[1].tmpref.size = strlen(ta_name) + 1;
    op.params[2].tmpref.buffer = (void*)sp;
    op.params[2].tmpref.size = strlen(sp) + 1;
    op.params[3].tmpref.buffer = (void*)content;
    op.params[3].tmpref.size = len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_OpenSession(ctx, sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		printf("TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

    return res;
}