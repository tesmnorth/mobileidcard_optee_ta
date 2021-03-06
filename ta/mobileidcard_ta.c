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

/**
 * This function is Trusted App Standart Function
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");
	return TEE_SUCCESS;
}

/**
 * This function is Trusted App Standart Function
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/**
 * This function is Trusted App Standart Function
 */
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
/**
 * Generates and saves 2048 bit RSA Key pair.
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
static TEE_Result generate_and_save_rsa_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle transientKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle persistentKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectInfo keyInfo;
	TEE_ObjectInfo keyInfo2;
	uint32_t keyId = 0;

	//Stroage accessibility
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

	//allocates a object with its size
	result = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE, &transientKey);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object handle : 0x%x", result);
		params[0].value.a = 0;
		goto cleanup;
	}

	//Generates a RSA Key Pair
	result = TEE_GenerateKey(transientKey, RSA_KEY_SIZE, NULL, 0);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to generate a transient key: 0x%x", result);
		params[0].value.a = 0;
		goto cleanup1;
	}

	TEE_GetObjectInfo1(transientKey, &keyInfo);

	//Saves RSA Key Pair on private storage persistently
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

	//return message for CA
	params[0].value.a = 1;

	cleanup2:
	TEE_CloseObject(persistentKey);
	cleanup1:
	TEE_FreeTransientObject(transientKey);
	cleanup:
	return result;
}

/**
 * Deletes RSA Key pair.
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
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

	//Pre-defined storage id on header file
	keyId = RSA_KEY_ID;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	//Opens RSA Key pair on private storage for deleting
	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &keyId, sizeof(keyId),
			flags, &key_handle);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		params[0].value.a = 0;
		goto cleanup;
	}

	//Return value for CA
	params[0].value.a = 1;
	//Deletes RSA Key Pair
	TEE_CloseAndDeletePersistentObject(key_handle);

	cleanup:
	return result;
}

/**
 * Deletes saved certificate
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
static TEE_Result delete_certificate(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle cert_handle = (TEE_ObjectHandle)NULL;
	uint32_t cert_id = 0;

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

	//Pre-defined storage id on header file
	cert_id = CERT_ID;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	//Opens certificate on private storage for deleting
	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &cert_id, sizeof(cert_id),
			flags, &cert_handle);

	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		params[0].value.a = 0;
		goto cleanup;
	}

	//Return value for CA
	params[0].value.a = 1;
	//Deletes certificate
	TEE_CloseAndDeletePersistentObject(cert_handle);

	cleanup:
	return result;
}

/**
 * Gets public exponent and modulus
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
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

/**
 * Saves certificate
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
static TEE_Result save_certificate(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle transientKey = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle persistentKey = (TEE_ObjectHandle)NULL;

	uint8_t *buffer;
	uint32_t buffer_len;
	uint32_t cert_id = 0;

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

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	cert_id =  CERT_ID;
	buffer = params[0].memref.buffer;
	buffer_len = params[0].memref.size;

	//Creates a new persistent object
	result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &cert_id, sizeof(cert_id),
			flags, TEE_HANDLE_NULL,  NULL, 0, &persistentKey);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to create a persistent key: 0x%x", result);
		params[1].value.a = 0;
		goto cleanup;
	}

	//Writes certificate to persistent object
	result = TEE_WriteObjectData(persistentKey, buffer, buffer_len);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to write data to  a persistent key: 0x%x", result);
		params[1].value.a = 0;
		goto cleanup1;
	}

	//Return value for CA
	params[1].value.a = 1;

	cleanup1:
	TEE_CloseObject(persistentKey);
	cleanup:
	TEE_FreeTransientObject(transientKey);
	return result;

}

/**
 * Gets certificates
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
static TEE_Result get_certificate(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle cert_handle = (TEE_ObjectHandle)NULL;
	TEE_ObjectInfo object_info;

	uint32_t read_bytes;
	uint8_t *buffer;
	uint32_t buffer_len = 0;

	uint32_t cert_id;

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

	//Pre-defined storage id on header file
	cert_id = CERT_ID;

	buffer = params[0].memref.buffer;
	buffer_len = params[0].memref.size;

	//Opens certificate on private storage for getting
	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &cert_id, sizeof(cert_id),
			flags, &cert_handle);
	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to open object handle : 0x%x", result);
		params[1].value.a = 0;
		goto cleanup;
	}

	//Gets certificate handle
	result = TEE_GetObjectInfo1(cert_handle, &object_info);
	if (result != TEE_SUCCESS ) {
		EMSG("Failed to get object info. TEE_GetObjectInfo1 res:0x%x ", result);
		params[1].value.a = 0;
		goto cleanup1;
	}

	if (object_info.dataSize > buffer_len)
	{
		params[0].memref.size = object_info.dataSize;
		result = TEE_ERROR_SHORT_BUFFER;
		goto cleanup1;
	}

	//Reads object to buffer
	result  = TEE_ReadObjectData(cert_handle, buffer, object_info.dataSize, &read_bytes);

	if (result != TEE_SUCCESS || read_bytes != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %u over %u", result, read_bytes, object_info.dataSize);
		params[1].value.a = 0;
		goto cleanup1;
	}

	params[0].memref.size = read_bytes;
	params[1].value.a = 1;

	cleanup1:
	TEE_CloseObject(cert_handle);
	cleanup:
	return result;

}

/**
 * Verifies given plain message and its signed message in params[]
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
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

	//Allocates an operationg with Algorithm and Operation type
	result = TEE_AllocateOperation(&operation, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
			TEE_MODE_VERIFY, RSA_KEY_SIZE * 2);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate operation: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup;
	}

	//Opens RSA key pair for verifing message
	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &keyId,
			sizeof(keyId), flags, &key_handle);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to open persistent key: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup1;
	}

	//Sets RSA Key pair for verifing operation
	result = TEE_SetOperationKey(operation, key_handle);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to set key: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup2;
	}

	//Verifing process
	result = TEE_AsymmetricVerifyDigest(operation, (TEE_Attribute *)NULL, 0,
			message, message_len, signed_message, signed_message_len);

	//Return value for CA
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

/**
 * Signs given hash  message  in params[]
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
static TEE_Result sign_message(uint32_t param_types, TEE_Param params[4])
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

	uint8_t *signed_message;
	uint32_t signed_message_len = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	message = params[0].memref.buffer;
	message_len = params[0].memref.size;

	signed_message = params[1].memref.buffer;
	signed_message_len = params[1].memref.size;

	keyId = RSA_KEY_ID;

	//Allocates an operationg with Algorithm and Operation type
	result = TEE_AllocateOperation(&operation, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
				TEE_MODE_SIGN, RSA_KEY_SIZE);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate operation: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup;
	}

	//Opens RSA key pair for signing message
	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &keyId,
			sizeof(keyId), flags, &key_handle);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to open persistent key: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup1;
	}

	//Sets RSA Key pair for signing operation
	result = TEE_SetOperationKey(operation, key_handle);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to set key: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup2;
	}

	//Signing process
	result = TEE_AsymmetricSignDigest(operation, (TEE_Attribute *)NULL, 0,
			message, message_len, signed_message, &signed_message_len);

	//Return value for CA
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

/**
 * Gives hash of plaing text with SHA 256
 * @params param_types - given parameter types on Client App
 * @params params[] - parameter values according to  types
 * @returns TEE_Result object
 */
static TEE_Result digest_message(uint32_t param_types, TEE_Param params[4])
{
	TEE_OperationHandle operation = (TEE_OperationHandle) NULL;
	TEE_Result result = TEE_SUCCESS;

	uint8_t *message;
	uint32_t message_len = 0;

	uint8_t *digest;
	uint32_t digest_len = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	message = params[0].memref.buffer;
	message_len = params[0].memref.size;

	digest = params[1].memref.buffer;
	digest_len = params[1].memref.size;

	//Allocates operation with algorithm
	result = TEE_AllocateOperation(&operation, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);

	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate operation: 0x%x", result);
		params[2].value.a = 0;
		goto cleanup;
	}

	//Digest process
	result = TEE_DigestDoFinal(operation, message, message_len, digest, &digest_len);

	//Return value for CA
	if (result == TEE_SUCCESS)
	{
		params[2].value.a = 1;
	}
	else
	{
		params[2].value.a = 0;
	}

	cleanup:
	return result;
}

/**
 * This function is Trusted App Standart Function
 */
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
		case TA_DELETE_CERTIFICATE_CMD:
			return delete_certificate(param_types, params);
		case TA_GET_PUBLICKEY_EXP_MOD_CMD:
			return get_public_key_exponent_modulus(param_types, params);
		case TA_VERIFY_CMD:
			return verify_message(param_types, params);
		case TA_SAVE_CERTIFICATE_CMD:
			return save_certificate(param_types, params);
		case TA_GET_CERTIFICATE_CMD:
			return get_certificate(param_types, params);
		case TA_SIGN_CMD:
			return sign_message(param_types, params);
		case TA_DIGEST_CMD:
			return digest_message(param_types, params);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

