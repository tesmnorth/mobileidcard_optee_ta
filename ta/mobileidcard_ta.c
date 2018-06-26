#define STR_TRACE_USER_TA "MOBILEIDCARD"
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/mobileidcard_ta.h"

static TEE_Result check_obj(TEE_ObjectInfo *o1, TEE_ObjectInfo *o2)
{
	if ((o1->objectType != o2->objectType) ||
			(o1->keySize != o2->keySize) ||
			(o1->maxKeySize != o2->maxKeySize) ||
			(o1->objectUsage != o2->objectUsage))
		return TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4],
		void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The EMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	DMSG("has been called\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void * sess_ctx)
{
	(void)&sess_ctx;
	DMSG("Goodbye!\n");
}

static TEE_Result generate_and_save_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle transientKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle persistentKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectInfo keyInfo;
	TEE_ObjectInfo keyInfo2;
	size_t keySize = 512;
	uint32_t keyId = 0;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	keyId = params[0].value.a;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	result = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, keySize, &transientKey);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object handle : 0x%x", result);
		goto cleanup1;
	}

	result = TEE_GenerateKey(transientKey, keySize, NULL, 0);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to generate a transient key: 0x%x", result);
		goto cleanup2;
	}

	TEE_GetObjectInfo1(transientKey, &keyInfo);
	result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &keyId, sizeof(keyId),
			flags, transientKey, NULL, 0, &persistentKey);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to create a persistent key: 0x%x", result);
		goto cleanup2;
	}

	TEE_GetObjectInfo1(persistentKey, &keyInfo2);
	result = check_obj(&keyInfo, &keyInfo2);

	if (result != TEE_SUCCESS) {
		EMSG("keyInfo and keyInfo2 are different");
		goto cleanup2;
	}

	TEE_CloseObject(persistentKey);
	cleanup2:
	TEE_FreeTransientObject(transientKey);
	cleanup1:
	return result;
}

static TEE_Result delete_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle keyHandle = (TEE_ObjectHandle)NULL;
	uint32_t keyId = 0;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	keyId = params[0].value.a;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &keyId, sizeof(keyId),
			flags, &keyHandle);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		goto cleanup;
	}

	TEE_CloseAndDeletePersistentObject(keyHandle);

	cleanup:
	return result;
}

static TEE_Result get_public_key_exponent_modulus(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;

	uint8_t buffer1[KEY_SIZE];
	uint32_t buffer_len1;

	uint8_t buffer2[KEY_SIZE];
	uint32_t buffer_len2;

	uint32_t rsa_keypair_id;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	rsa_keypair_id = params[0].value.a;

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &rsa_keypair_id, sizeof(rsa_keypair_id),
			flags, &rsa_keypair);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		goto cleanup;
	}

	/*get the exponent value, as an octet string */
	buffer_len1 = sizeof(buffer1);
	DMSG("Buffer1 Len : %u", buffer_len1);
	result = TEE_GetObjectBufferAttribute(rsa_keypair, TEE_ATTR_RSA_PUBLIC_EXPONENT, buffer1, &buffer_len1);
	DMSG("Buffer1 Len (After): %u", buffer_len1);
	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to get object buffer attribute. TEE_GetObjectBufferAttribute res: 0x%x", result);
		goto cleanup;
	}

	/*get the modulus value, as an octet string */
	buffer_len2 = sizeof(buffer2);
	DMSG("Buffer2 Len : %u", buffer_len2);
	result = TEE_GetObjectBufferAttribute(rsa_keypair, TEE_ATTR_RSA_MODULUS, buffer2, &buffer_len2);
	DMSG("Buffer2 Len (After) : %u", buffer_len2);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to get object buffer attribute. TEE_GetObjectBufferAttribute res: 0x%x", result);
		goto cleanup;
	}

	params[1].memref.buffer = buffer1;
	params[1].memref.size = buffer_len1;

	params[2].memref.buffer = buffer2;
	params[2].memref.size = buffer_len2;

	cleanup:
	TEE_CloseAndDeletePersistentObject(rsa_keypair);

	return result;
}


TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
		uint32_t param_types, TEE_Param params[4])
{
	/* Unused parameters */
	(void)&sess_ctx;

	switch (cmd_id) {
	case TA_GENERATE_KEY_CMD:
		return generate_and_save_key(param_types, params);
	case TA_DELETE_KEY_CMD:
		return delete_key(param_types, params);
	case TA_GET_PUBLICKEY_EXP_MOD_CMD:
		return get_public_key_exponent_modulus(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

