/* 
 * Ripped from CryptHook
 * AES TCP wrapper
 * www.chokepoint.net
 * Packet Format:
 * [algo][iv][hmac][payload]
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>

#include "crypthook.h"
#include "const.h"
#include "xor.h"

#define KEY_SIZE 32  	        // AES 256 in GCM mode.
#define IV_SIZE 12				// 12 bytes used for AES 256 in GCM mode

#define PACKET_HEADER 0x17		// Packet Identifier added to each header

// 1 byte packet identifier
// 12 bytes IV
// 16 bytes MAC
#define HEADER_SIZE 31 

// Used in PBKDF2 key generation. CHANGE THIS FROM DEFAULT
#define ITERATIONS 1000					

static char glob_key[KEY_SIZE]="\00";

static void gen_key(void) {
	char *passphrase = strdup(PASSPHRASE);
	char *key_salt = strdup(KEY_SALT);
	x(passphrase);
	x(key_salt);
	
	PKCS5_PBKDF2_HMAC_SHA1(passphrase,strlen(passphrase),(const unsigned char *)key_salt,strlen(key_salt),ITERATIONS,KEY_SIZE,(unsigned char *)glob_key);
	free(passphrase);
	free(key_salt);
}

static int encrypt_data(char *in, int len, char *out) {
	unsigned char outbuf[MAX_LEN];
	unsigned char temp[MAX_LEN];
	unsigned char iv[IV_SIZE];
	unsigned char tag[16];
	
	unsigned char *step;
	int tmplen=0, outlen=0;

	// copy plain text message into temp
	memset(temp,0x00,MAX_LEN);
	memcpy(temp,in,len);
	
	if (glob_key[0] == 0x00) // Generate key if its the first packet
		gen_key(); 
	RAND_bytes(iv,IV_SIZE); // Generate random IV
	
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init (ctx);
	EVP_EncryptInit_ex (ctx, EVP_aes_256_gcm() , NULL, (const unsigned char *)glob_key, (const unsigned char *)iv);

	if (!EVP_EncryptUpdate (ctx, outbuf, &outlen, (const unsigned char *)temp, len)) {
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}

	if (!EVP_EncryptFinal_ex (ctx, outbuf + outlen, &tmplen)) {
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
	
	// Add header information
	out[0]=PACKET_HEADER;
	out[1]=(0xff00&(len+HEADER_SIZE))>>8;
	out[2]=(0xff&(len+HEADER_SIZE));
	step=(unsigned char *)&out[3];	
	memcpy(step,iv,IV_SIZE);
	step+=IV_SIZE;
	memcpy(step,tag,sizeof(tag));
	step+=sizeof(tag);
	memcpy(step,outbuf,outlen+tmplen);
	
	EVP_CIPHER_CTX_cleanup (ctx);
	return outlen+tmplen+HEADER_SIZE;
}

static int decrypt_data(char *in, int len, char *out) {
	unsigned char outbuf[MAX_LEN];
	unsigned char iv[IV_SIZE];
	unsigned char tag[16];
	char *step;
	
	int tmplen=0, outlen=0;
	
	memset(outbuf,0x00,MAX_LEN);
	
	// header information
	step=in+3;
	memcpy(iv,step,IV_SIZE); // Extract the IV
	step+=IV_SIZE;
	memcpy(tag,step,16); // Extract the MAC
	step+=16;

	if (glob_key[0] == 0x00)   // Generate key if its the first packet
		gen_key(); 
	
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init (ctx);
	EVP_DecryptInit_ex (ctx, EVP_aes_256_gcm() , NULL, (const unsigned char *)glob_key, (const unsigned char *)iv);
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
	
	if (!EVP_DecryptUpdate (ctx, outbuf, &outlen, (const unsigned char *)step, len)) {
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

	if (!EVP_DecryptFinal_ex (ctx, outbuf + outlen, &tmplen)) {
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_cleanup (ctx);
	
	memcpy(out,outbuf,outlen+tmplen);
	
	return len;
}

/* Hook recv and decrypt the data before returning to the program */
ssize_t crypt_read(int sockfd, void *buf, size_t len) {
	char outbuf[MAX_LEN];
	unsigned char temp[MAX_LEN];
	char *step;
	
	int outlen, ret, flags=0, packet_len;

	memset(outbuf,0x00,MAX_LEN);
	memset(temp,0x00,MAX_LEN);
		
	if (sockfd == 0) // Y U CALL ME W/ SOCKFD SET TO ZERO!?!?
		return recv(sockfd, buf, len, flags);
	
	ret = recv(sockfd, (void *)temp, 3, MSG_PEEK);
	
	if (ret < 1) { // Nothing to decrypt 
		return ret;
	}

	if (temp[0] != PACKET_HEADER)
		return 0;

	packet_len = (temp[1]<<8)+temp[2];
	
	ret = recv(sockfd, (void *)temp, packet_len, flags);
	outlen = decrypt_data((char *)temp,ret - HEADER_SIZE,&outbuf[0]);

	memcpy((void*)buf,(void*)outbuf,(size_t)outlen);
	
	return outlen;
}

/* Hook send and encrypt data first */
ssize_t crypt_write(int sockfd, const void *buf, size_t len) {
	char outbuf[MAX_LEN];
	int outlen, ret, flags=0;
	
	memset(outbuf,0x00,MAX_LEN);
		
	outlen = encrypt_data((char *)buf, len, &outbuf[0]);
	if (outlen == 0)
		return 0;
		
	// Send the encrypted data
	ret = send(sockfd, (void *)outbuf, outlen, flags); 

	if (ret == -1) {
		return -1;
	}

	return len; 
}
