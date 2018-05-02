#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "include/mobileidcard_ta.h"

#define BigIntSizeInU32(n) ((((n)+31)/32)+2)

void generateAndSaveKey(uint32_t keyId)
{
	TEEC_Result result;
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_UUID uuid = TA_MIC_UUID;
	uint32_t err_origin;

	result = TEEC_InitializeContext(NULL, &context);
	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", result);

	result = TEEC_OpenSession(&context, &session, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				result, err_origin);

	memset(&operation, 0, sizeof(operation));

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE);

	operation.params[0].value.a = keyId;

	result = TEEC_InvokeCommand(&session, TA_GENERATE_KEY_CMD, &operation, &err_origin);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand (GENERATE SAVE KEY) failed with code 0x%x origin 0x%x",
				result, err_origin);

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);
}

void deleteKey(uint32_t keyId)
{
	TEEC_Result result;
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_UUID uuid = TA_MIC_UUID;
	uint32_t err_origin;

	result = TEEC_InitializeContext(NULL, &context);
	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", result);

	result = TEEC_OpenSession(&context, &session, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				result, err_origin);

	memset(&operation, 0, sizeof(operation));

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE);

	operation.params[0].value.a = keyId;

	result = TEEC_InvokeCommand(&session, TA_DELETE_KEY_CMD, &operation, &err_origin);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand (DELETE KEY) failed with code 0x%x origin 0x%x",
				result, err_origin);

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);
}

void getPublicKey(uint32_t keyId)
{
	TEEC_Result result;
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_UUID uuid = TA_MIC_UUID;
	uint32_t err_origin;

	size_t keySize = 512;

	uint32_t exponentLen = BigIntSizeInU32(keySize) * sizeof(uint32_t);
	uint32_t *exponent = malloc(exponentLen);

	uint32_t modulusLen = BigIntSizeInU32(keySize) * sizeof(uint32_t);
	uint32_t *modulus = malloc(modulusLen);

	result = TEEC_InitializeContext(NULL, &context);
	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", result);

	result = TEEC_OpenSession(&context, &session, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				result, err_origin);

	memset(&operation, 0, sizeof(operation));

	operation.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_NONE);

	operation.params[0].value.a = keyId;

	operation.params[1].tmpref.buffer = &exponent;
	operation.params[1].tmpref.size = exponentLen;

	operation.params[2].tmpref.buffer = &modulus;
	operation.params[2].tmpref.size = modulusLen;

	result = TEEC_InvokeCommand(&session, TA_GET_PUBLICKEY_CMD, &operation, &err_origin);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand (GET PUBLIC KEY) failed with code 0x%x origin 0x%x",
				result, err_origin);

	free(exponent);
	free(modulus);

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);
}

int main (int argc, char *argv[])
{
	uint32_t keyId = 100;
	generateAndSaveKey(keyId);
	deleteKey(100);
	printf("Deleted\n");

	return 0;
}
