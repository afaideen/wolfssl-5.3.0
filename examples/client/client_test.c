
#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>
#define SERV_PORT 11111

int main()
{
	int sockfd;
	//SOCKET sockfd;
	WOLFSSL_CTX* ctx;
	WOLFSSL* ssl;
	//WOLFSSL_METHOD* method;
	wolfSSL_method_func method = NULL;
	struct  sockaddr_in servAddr;
	char* host = (char*)"127.0.0.1";
	const char message[] = "Hi there!";
	int ret, conn;
	int err = 0;
	int    minDhKeyBits = DEFAULT_MIN_DHKEY_BITS;
	const char* ourCert;
	const char* ourKey;
	const char* verifyCert;
	int verify_flags = 0;

	//ourCert = cliCertFile;
	//ourKey = cliKeyFile;
	//verifyCert = caCertFile;
	verifyCert = "../../certs/ca-cert.pem";
	ourCert = "../../certs/client-cert.pem";
	ourKey = "../../certs/client-key.pem";
	
	StartTCP();
	//printf(message);
	///* create and set up socket */
	//sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	//if (sockfd == INVALID_SOCKET) {
	//
	//	wprintf(L"socket function failed with error: %ld\n", WSAGetLastError());
	//	WSACleanup();
	//	return 1;
	//}
	//memset(&servAddr, 0, sizeof(servAddr));
	//servAddr.sin_family = AF_INET;
	//servAddr.sin_port = htons(SERV_PORT);
	//servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	///* connect to socket */
	//conn = connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr));
	//while (conn == -1)
	//{
	//	conn = connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr));
	//}

	/* initialize wolfssl library */
	wolfSSL_Init();
	method = wolfTLSv1_2_client_method(); /* use TLS v1.2 */
	//method = wolfTLSv1_2_client_method_ex;

	/* make new ssl context */
	if ((ctx = wolfSSL_CTX_new(method)) == NULL) 
	{
		err_sys("wolfSSL_CTX_new error");
	}
	/*if (method != NULL) {
		ctx = wolfSSL_CTX_new(method(NULL));
		if (ctx == NULL)
			err_sys("unable to get ctx");
	}*/

	//if (wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)minDhKeyBits)
	//	!= WOLFSSL_SUCCESS) {
	//	err_sys("Error setting minimum DH key size");
	//}
//#ifdef WOLFSSL_ENCRYPTED_KEYS
//	wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
//#endif

	

	if (wolfSSL_CTX_use_certificate_chain_file(ctx, ourCert)
		!= WOLFSSL_SUCCESS) {
		wolfSSL_CTX_free(ctx); ctx = NULL;
		err_sys("can't load client cert file, check file and run from"
			" wolfSSL home dir");
	}
	if (wolfSSL_CTX_use_PrivateKey_file(ctx, ourKey, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) 
	{
		wolfSSL_CTX_free(ctx); ctx = NULL;
		err_sys("can't load client private key file, check file and run "
			"from wolfSSL home dir");
	}

	/* make new wolfSSL struct */
	if ((ssl = wolfSSL_new(ctx)) == NULL) {
		err_sys("wolfSSL_new error");
	}
	

	/* Add cert to ctx */
	//if (wolfSSL_CTX_load_verify_locations(ctx, "../../certs/ca-cert.pem", 0) != SSL_SUCCESS) 
	if( wolfSSL_CTX_load_verify_locations_ex(ctx, verifyCert, 0, verify_flags) != WOLFSSL_SUCCESS )
	{
		err_sys("Error loading certs/ca-cert.pem");
	}
	wolfSSL_KeepArrays(ssl);
	tcp_connect((SOCKET *)&sockfd, host, SERV_PORT, 0, 0, ssl);
	/* Connect wolfssl to the socket, server, then send message */
	wolfSSL_set_fd(ssl, sockfd);
	do {
		err = 0; /* reset error */
		ret = wolfSSL_connect(ssl);

		if (ret != WOLFSSL_SUCCESS) 
			err = wolfSSL_get_error(ssl, 0);
	} while (err == WC_PENDING_E);
	if (ret != WOLFSSL_SUCCESS) {
		err_sys("SSL_connect failed");
	}
	wolfSSL_write(ssl, message, strlen(message));

	/* frees all data before client termination */
	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();


	return 0;
}