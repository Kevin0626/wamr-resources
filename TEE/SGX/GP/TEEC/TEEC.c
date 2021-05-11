#include "tee_client_api.h"
#include <unistd.h>
#include <pwd.h>
#include "../samples/hello_world/host/Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_error.h"
#include <cstdio>

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
	return TEEC_SUCCESS;
}


void TEEC_FinalizeContext(TEEC_Context *context)
{
    memset(context, 0, sizeof(*context));
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
    if (ecall_gp_open_session(g_eid, &ret, operation->paramTypes,
	                          operation->params, &session->session_id) != SGX_SUCCESS) {
		return -1;
	}

    session->ctx = context;

	return ret;
}


void TEEC_CloseSession(TEEC_Session *session)
{
	ecall_gp_close_session(g_eid, session->session_id);
    memset(session,0, sizeof(*session));
}


TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
			       uint32_t commandID,
			       TEEC_Operation *operation,
			       uint32_t *returnOrigin)
{
	TEEC_Result ret;

    if(ecall_gp_invoke(g_eid, &ret, session->session_id, commandID,
					          operation->paramTypes, operation->params) != SGX_SUCCESS) {
		return -1;
	}

	return ret;
}
