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

static TEE_Result generate_and_save_rsa_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle transientKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle persistentKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectInfo keyInfo;
	TEE_ObjectInfo keyInfo2;
	uint32_t keyId = 0;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	keyId = RSA_KEY_ID;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	result = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE, &transientKey);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object handle : 0x%x", result);
		params[0].value.a = 0;
		goto cleanup;
	}

	result = TEE_GenerateKey(transientKey, RSA_KEY_SIZE, NULL, 0);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to generate a transient key: 0x%x", result);
		params[0].value.a = 0;
		goto cleanup1;
	}

	TEE_GetObjectInfo1(transientKey, &keyInfo);
	result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &keyId, sizeof(keyId),
			flags, transientKey, NULL, 0, &persistentKey);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to create a persistent key: 0x%x", result);
		params[0].value.a = 0;
		goto cleanup1;
	}

	TEE_GetObjectInfo1(persistentKey, &keyInfo2);
	result = check_obj(&keyInfo, &keyInfo2);

	if (result != TEE_SUCCESS) {
		EMSG("keyInfo and keyInfo2 are different");
		params[0].value.a = 0;
		goto cleanup2;
	}

	params[0].value.a = 1;

	cleanup2:
	TEE_CloseObject(persistentKey);
	cleanup1:
	TEE_FreeTransientObject(transientKey);
	cleanup:
	return result;
}

static TEE_Result delete_rsa_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle key_handle = (TEE_ObjectHandle)NULL;
	uint32_t keyId = 0;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	keyId = RSA_KEY_ID;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &keyId, sizeof(keyId),
			flags, &key_handle);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		params[0].value.a = 0;
		goto cleanup;
	}

	params[0].value.a = 1;
	TEE_CloseAndDeletePersistentObject(key_handle);

	cleanup:
	return result;
}

static TEE_Result delete_signed_public_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle signed_public_key_handle = (TEE_ObjectHandle)NULL;
	uint32_t signedPublicKeyId = 0;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	signedPublicKeyId = SIGNED_PUBLIC_KEY_ID;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &signedPublicKeyId, sizeof(signedPublicKeyId),
			flags, &signed_public_key_handle);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		params[0].value.a = 0;
		goto cleanup;
	}

	params[0].value.a = 1;
	TEE_CloseAndDeletePersistentObject(signed_public_key_handle);

	cleanup:
	return result;
}

static TEE_Result get_public_key_exponent_modulus(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;

	uint8_t *buffer1;
	uint32_t buffer_len1 = 0;

	uint8_t *buffer2;
	uint32_t buffer_len2 = 0;

	uint32_t rsa_keypair_id;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	rsa_keypair_id = RSA_KEY_ID;
	buffer1 = params[0].memref.buffer;
	buffer2 = params[1].memref.buffer;

	buffer_len1 = params[0].memref.size;
	buffer_len2 = params[1].memref.size;

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &rsa_keypair_id, sizeof(rsa_keypair_id),
			flags, &rsa_keypair);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		params[2].value.a = 0;
		goto cleanup;
	}

	/*get the exponent value, as an octet string */
	result = TEE_GetObjectBufferAttribute(rsa_keypair, TEE_ATTR_RSA_PUBLIC_EXPONENT, buffer1, &buffer_len1);
	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to get object buffer attribute. TEE_GetObjectBufferAttribute res: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup1;
	}

	/*get the modulus value, as an octet string */
	result = TEE_GetObjectBufferAttribute(rsa_keypair, TEE_ATTR_RSA_MODULUS, buffer2, &buffer_len2);
	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to get object buffer attribute. TEE_GetObjectBufferAttribute res: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup1;
	}

	params[0].memref.size = buffer_len1;
	params[1].memref.size = buffer_len2;
	params[2].value.a = 1;

	cleanup1:
	TEE_CloseObject(rsa_keypair);
	cleanup:
	return result;
}

static TEE_Result save_signed_public_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle transientKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle persistentKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectInfo keyInfo;
	TEE_ObjectInfo keyInfo2;
	TEE_Attribute secret_value;

	uint32_t signedPublicKeyId = 0;
	uint32_t signed_pk_len = 0;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	signedPublicKeyId = SIGNED_PUBLIC_KEY_ID;
	signed_pk_len = params[0].memref.size;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("TESSSSSSSSSSSSSSSSSSSTTTTTTTTTTTTTTTTTTTT %i", signed_pk_len);
	result = TEE_AllocateTransientObject(TEE_TYPE_DATA, signed_pk_len, &transientKey);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object handle : 0x%x", result);
		params[1].value.a = 0;
		goto cleanup;
	}

	secret_value.content.ref.buffer = params[0].memref.buffer;
	secret_value.content.ref.length = params[0].memref.size;

	result = TEE_PopulateTransientObject(transientKey, &secret_value, 1);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to populate signed public key to a transient key: 0x%x", result);
		params[1].value.a = 0;
		goto cleanup1;
	}

	TEE_GetObjectInfo1(transientKey, &keyInfo);
	result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &signedPublicKeyId, sizeof(signedPublicKeyId),
			flags, transientKey, NULL, 0, &persistentKey);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to create a persistent key: 0x%x", result);
		params[1].value.a = 0;
		goto cleanup1;
	}

	TEE_GetObjectInfo1(persistentKey, &keyInfo2);
	result = check_obj(&keyInfo, &keyInfo2);

	if (result != TEE_SUCCESS) {
		EMSG("keyInfo and keyInfo2 are different");
		params[1].value.a = 0;
		goto cleanup2;
	}

	params[1].value.a = 1;

	cleanup2:
	TEE_CloseObject(persistentKey);
	cleanup1:
	TEE_FreeTransientObject(transientKey);
	cleanup:
	return result;

}

static TEE_Result get_signed_public_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle signed_pk_handle = (TEE_ObjectHandle)NULL;

	uint8_t *buffer;
	uint32_t buffer_len = 0;

	uint32_t signed_pk_id;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	signed_pk_id = SIGNED_PUBLIC_KEY_ID;

	buffer = params[0].memref.buffer;
	buffer_len = params[0].memref.size;

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &signed_pk_id, sizeof(signed_pk_id),
			flags, &signed_pk_handle);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		params[2].value.a = 0;
		goto cleanup;
	}

	result = TEE_GetObjectBufferAttribute(signed_pk_handle, TEE_ATTR_SECRET_VALUE, buffer, &buffer_len);
	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to get object buffer attribute. TEE_GetObjectBufferAttribute res: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup1;
	}

	params[0].memref.size = buffer_len;
	params[1].value.a = 1;

	cleanup1:
	TEE_CloseObject(signed_pk_handle);
	cleanup:
	return result;

}

static TEE_Result verify_message(uint32_t param_types, TEE_Param params[4])
{
	TEE_OperationHandle operation = (TEE_OperationHandle) NULL;
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle key_handle = (TEE_ObjectHandle)NULL;
	uint32_t keyId = 0;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;

	uint8_t *message;
	uint32_t message_len = 0;

	uint8_t *signed_message = NULL;
	uint32_t signed_message_len = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	message = params[0].memref.buffer;
	message_len = params[0].memref.size;

	signed_message = params[1].memref.buffer;
	signed_message_len = params[1].memref.size;

	keyId = RSA_KEY_ID;

	result = TEE_AllocateOperation(&operation, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
			TEE_MODE_VERIFY, RSA_KEY_SIZE * 2);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate operation: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup;
	}

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &keyId,
			sizeof(keyId), flags, &key_handle);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to open persistent key: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup1;
	}

	result = TEE_SetOperationKey(operation, key_handle);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to set key: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup2;
	}

	result = TEE_AsymmetricVerifyDigest(operation, (TEE_Attribute *)NULL, 0,
			message, message_len, signed_message, signed_message_len);

	if (result == TEE_SUCCESS)
	{
		params[2].value.a = 1;
	}
	else
	{
		params[2].value.a = 0;
	}

	cleanup2:
	TEE_CloseObject(key_handle);
	cleanup1:
	TEE_FreeOperation(operation);
	cleanup:
	return result;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
		uint32_t param_types, TEE_Param params[4])
{
	/* Unused parameters */
	(void)&sess_ctx;

	switch (cmd_id) {
		case TA_GENERATE_RSA_KEY_CMD:
			return generate_and_save_rsa_key(param_types, params);
		case TA_DELETE_RSA_KEY_CMD:
			return delete_rsa_key(param_types, params);
		case TA_DELETE_SIGNED_PUBLIC_KEY_CMD:
			return delete_signed_public_key(param_types, params);
		case TA_GET_PUBLICKEY_EXP_MOD_CMD:
			return get_public_key_exponent_modulus(param_types, params);
		case TA_VERIFY_CMD:
			return verify_message(param_types, params);
		case TA_SAVE_SIGNED_PUBLIC_KEY_CMD:
			return save_signed_public_key(param_types, params);
		case TA_GET_SIGNED_PUBLIC_KEY_CMD:
			return get_signed_public_key(param_types, params);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

