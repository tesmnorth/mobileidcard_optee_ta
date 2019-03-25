#ifndef MOBILEIDCARD_TA_H_
#define MOBILEIDCARD_TA_H_

#define TA_MIC_UUID { 0xc4d22850, 0x20f1, 0x4b12, \
					{0x82, 0x3a, 0xeb, 0x7a, 0xef, 0xba, 0xe4, 0x62} }

#define TA_GENERATE_RSA_KEY_CMD 0
#define TA_DELETE_RSA_KEY_CMD 1
#define TA_GET_PUBLICKEY_EXP_MOD_CMD 2
#define TA_DELETE_CERTIFICATE_CMD 3
#define TA_SAVE_CERTIFICATE_CMD 4
#define TA_GET_CERTIFICATE_CMD 5
#define TA_SIGN_CMD 6
#define TA_DIGEST_CMD 7

#define TA_VERIFY_CMD 8

#define RSA_KEY_SIZE 2048
#define RSA_KEY_ID 100
#define CERT_ID 101

#endif
