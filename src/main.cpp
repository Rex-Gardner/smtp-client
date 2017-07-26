#include <iostream>
#include <openssl\ssl.h>
#include <openssl\bio.h>
#include <openssl\err.h>
#include "base64.h"

using namespace std;

#pragma comment(lib, "Ws2_32.lib")

#define CLIENT_VERSION "v1.0"
#define MAX_SMTP_MESSAGE_STRING_LENGTH 998	//without CRLF symbols
#define MAX_SMTP_COMMAND_STRING_LENGTH 510	//without CRLF symbols

BIO *bio;
SSL *ssl;
SSL_CTX *ctx;
bool isBase64Encoded = false;

bool sendMail(const char *pLogin,
	const char *pPassword,
	const char *pRcptAddr,
	char *pSubject = 0,
	char *pMessage = 0,
	char *pSenderName = 0,
	bool isDebugMode = false)
{
	/*
	Return values for sendMail function:
	false - Failed
	true  - Success
	*/
	char szText[MAX_SMTP_MESSAGE_STRING_LENGTH + 3];	//+3 for CRLF and \0 symbols
	char *pMessageCode;
	char szQuitMsg[7];
	memset(szQuitMsg, 0, sizeof(szQuitMsg));
	strcpy(szQuitMsg, "QUIT\r\n");
	int iMaxMsgSize = 20000000;	//20mb 
	bool is8BitMimeMode = false;

	//Starting dialogue with SMTP server
	memset(szText, 0, sizeof(szText));
	//Getting HELLO message from SMTP server
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;

	//Hello-string preparation
	memset(szText, 0, sizeof(szText));
	strcpy(szText, "EHLO smtp.mail.ru\r\n");
	//Sending our EHLO (extended HELLO) message to SMTP server
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Getting list of server extensions
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;

	//Checking SIZE extension
	if (strstr(szText, "SIZE"))
	{
		char *pTmp = strstr(szText, "SIZE") + 5;
		char szTmp[16];
		memset(szTmp, 0, sizeof(szTmp));
		int i = 0;

		while (true)
		{
			if (pTmp[i] == '\r')
				break;
			szTmp[i] = pTmp[i];
			i++;
		}

		iMaxMsgSize = atoi(szTmp);
	}

	//Checking message size
	if (sizeof(pMessage)+2 >= iMaxMsgSize)
	{
		if (isDebugMode) cout << "error - This message is too large for sending." << endl;
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return false;
	}

	//Checking 8BITMIME extension
	if (strstr(szText, "8BITMIME"))
	{
		is8BitMimeMode = true;
	}

	//Checking AUTH types extension
	if (!strstr(szText, "LOGIN"))
	{
		//Our simple client can't pass another type of authentication :(
		if (isDebugMode) cout << "error - Server doesn't support AUTH LOGIN method." << endl;
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return true;
	}

	//Authentication and encryption
	memset(szText, 0, sizeof(szText));
	strcpy(szText, "AUTH LOGIN\r\n");
	//Sending AUTH command
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Getting invitation to send our login
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;

	//Login preparation
	memset(szText, 0, sizeof(szText));
	base64(szText, pLogin, strlen(pLogin)*sizeof(pLogin[0]));
	strcat(szText, "\r\n");
	//Sending our encoded login
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Getting invitation to send our password
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;
	pMessageCode = strtok(szText, " ");
	if (atoi(pMessageCode) != 334)	//Auth invitation code
	{
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return false;
	}

	//Password preparation
	memset(szText, 0, sizeof(szText));
	base64(szText, pPassword, strlen(pPassword)*sizeof(pPassword[0]));
	strcat(szText, "\r\n");
	//Sending our encoded password
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Geting message with authentication status
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;
	pMessageCode = strtok(szText, " ");
	if (atoi(pMessageCode) != 235)	//Auth success code
	{
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return false;
	}

	//Email string preparation
	memset(szText, 0, sizeof(szText));
	strcpy(szText, "MAIL FROM: <");
	strcat(szText, pLogin);
	strcat(szText, ">");
	//Using 8bit symbols
	if (is8BitMimeMode)
		strcat(szText, " BODY=8BITMIME");
	strcat(szText, "\r\n");
	//Sending our email address
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Getting status of validation of our email address
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;
	pMessageCode = strtok(szText, " ");
	if (atoi(pMessageCode) != 250)	//Code of validity of the sender mail address
	{
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return false;
	}

	//Recipient email address preparation
	memset(szText, 0, sizeof(szText));
	strcpy(szText, "RCPT TO: <");
	strcat(szText, pRcptAddr);
	strcat(szText, ">\r\n");
	//Sending email recipient email address
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Getting status of validation of recipient email address
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;
	pMessageCode = strtok(szText, " ");
	if (atoi(pMessageCode) != 250)	//Code of validity of the rcpt mail address
	{
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return false;
	}

	//Message data preparation
	memset(szText, 0, sizeof(szText));
	strcpy(szText, "DATA\r\n");
	//Sending command to start describing the content of the message
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Getting message about start describing the content
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;
	pMessageCode = strtok(szText, " ");
	if (atoi(pMessageCode) != 354)	//Code of starting the data building process
	{
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return false;
	}

	//Sender string preparation
	memset(szText, 0, sizeof(szText));
	strcpy(szText, "FROM: ");
	if (pSenderName != 0)	//Checking the presence of the sender's name
		strcat(szText, pSenderName);
	strcat(szText, "<");
	strcat(szText, pLogin);
	strcat(szText, ">\r\n");
	//Sending our email address
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));

	//Recipient string preparation
	strcpy(szText, "TO: <");
	strcat(szText, pRcptAddr);
	strcat(szText, ">\r\n");
	//Sending recipient email address
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;

	//Subject string preparation
	if (pSubject != 0)
	{
		memset(szText, 0, sizeof(szText));
		strcpy(szText, "SUBJECT: ");
		strcat(szText, pSubject);
		strcat(szText, "\r\n");
		//Sending subject string
		BIO_write(bio, szText, strlen(szText));
		if (isDebugMode) cout << "send - " << szText << endl;
	}

	if (pMessage != 0)
	{
		memset(szText, 0, sizeof(szText));
		int iSmtpStringsCount = 0;
		//Splitting a large message into lines (if required)
		while (strlen(pMessage) >= MAX_SMTP_MESSAGE_STRING_LENGTH)
		{
			memcpy(szText, pMessage, MAX_SMTP_MESSAGE_STRING_LENGTH);
			szText[MAX_SMTP_MESSAGE_STRING_LENGTH] = '\r';
			szText[MAX_SMTP_MESSAGE_STRING_LENGTH + 1] = '\n';
			szText[MAX_SMTP_MESSAGE_STRING_LENGTH + 2] = 0;
			pMessage += MAX_SMTP_MESSAGE_STRING_LENGTH;	//Move the message pointer
			//Sending one line of the large message
			BIO_write(bio, szText, strlen(szText));
			if (isDebugMode) cout << "send - " << szText << endl;
			iSmtpStringsCount++;
		}
		memset(szText, 0, sizeof(szText));
		strcpy(szText, pMessage);
		strcat(szText, "\r\n");
		//Sending last (or single) line of the message
		BIO_write(bio, szText, strlen(szText));
		if (isDebugMode) cout << "send - " << szText << endl;
		//Return the message pointer to the original value
		pMessage -= MAX_SMTP_MESSAGE_STRING_LENGTH*iSmtpStringsCount;
	}

	//Finishing the message sending
	memset(szText, 0, sizeof(szText));
	strcpy(szText, ".\r\n");
	//Sending single '.' symbol
	BIO_write(bio, szText, strlen(szText));
	if (isDebugMode) cout << "send - " << szText << endl;
	memset(szText, 0, sizeof(szText));
	//Getting status of message sending
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;
	pMessageCode = strtok(szText, " ");
	if (atoi(pMessageCode) != 250)	//Code of successful sending of the message
	{
		BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
		if (isDebugMode) cout << "send - " << szQuitMsg << endl;
		memset(szText, 0, sizeof(szText));
		BIO_read(bio, szText, sizeof(szText));
		if (isDebugMode) cout << "recv - " << szText << endl;
		return false;
	}

	//Parting with SMTP server
	BIO_write(bio, szQuitMsg, strlen(szQuitMsg));
	if (isDebugMode) cout << "send - " << szQuitMsg << endl;
	memset(szText, 0, sizeof(szText));
	//Getting message about closing of connection
	BIO_read(bio, szText, sizeof(szText));
	if (isDebugMode) cout << "recv - " << szText << endl;
	memset(szText, 0, sizeof(szText));

	return true;
}

DWORD WINAPI Thread(LPVOID)
{
	char szText[MAX_SMTP_COMMAND_STRING_LENGTH+3];	//max smtp command string length with CRLF and \0 symbols

	while (true)
	{
		memset(szText, 0, sizeof(szText));
		//Getting SMTP commands from server
		BIO_read(bio, szText, sizeof(szText));
		cout << "recv - " << szText << endl;

		char *pMessageCode = strtok(szText, " ");
		if (atoi(pMessageCode) == 334)
			isBase64Encoded = true;

		if (atoi(pMessageCode) == 235)
			isBase64Encoded = false;

		if (atoi(pMessageCode) == 221)
			break;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "Russian");
	cout << "SMTP client " << CLIENT_VERSION << " by Rexxx" << endl;

	//Initialization of SSL connection
	SSL_library_init();
	ERR_load_BIO_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	ctx = SSL_CTX_new(SSLv23_client_method());
	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	//Using MAIL.RU SMTP server with 465 port for SSL connection
	BIO_set_conn_hostname(bio, "smtp.mail.ru:465");

	//Checking connection between client and SMTP server
	if (BIO_do_connect(bio) <= 0)
	{
		cout << "error - BIO_do_connect failed." << endl;
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		return 1;
	}

	if (argc >= 7)
	{
		char *pLogin=0, *pPasswd=0, *pRcpt=0, *pSbj=0, *pMsg=0, *pName=0;
		bool isDebug = false;

		for (int i = 1; i < argc-1; i++)
		{
			if (!strcmp(argv[i], "-login"))
				pLogin = argv[i + 1];

			if (!strcmp(argv[i], "-passwd"))
				pPasswd = argv[i + 1];

			if (!strcmp(argv[i], "-rcpt"))
				pRcpt = argv[i + 1];

			if (!strcmp(argv[i], "-sbj"))
				pSbj = argv[i + 1];

			if (!strcmp(argv[i], "-msg"))
				pMsg = argv[i + 1];

			if (!strcmp(argv[i], "-name"))
				pName = argv[i + 1];

			if (!strcmp(argv[i], "-dbg"))
				isDebug = true;
		}

		if (!strcmp(argv[argc-1], "-dbg"))
			isDebug = true;

		if (pLogin == 0 || pPasswd == 0 || pRcpt == 0)
		{
			cout << "Parameters '-login', '-passwd' and '-rcpt' are required." << endl;
			cout << "Check your parameters and try again." << endl;
			return 1;
		}

		if (sendMail(pLogin, pPasswd, pRcpt, pSbj, pMsg, pName, isDebug))
		{
			if (!isDebug)
				cout << "Message have been send successfully!" << endl;
		}
		else
		{
			if (!isDebug)
			{
				cout << "Something went wrong. Use '-dbg' parameter for ";
				cout << "getting more information."<<endl;
			}
				
		}
	}
	else
	{
		cout << "Using:" << endl;
		cout << "    sendMail -login <sender@example.org> -passwd <email password>\n";
		cout << "             -rcpt <recipient@example.org> [-sbj < \"message subject\">]\n";
		cout << "             [-msg < \"Message content\">] [-name <\"Sender name\">] [-dbg]\n";
		cout << endl;
		
		char szText[MAX_SMTP_COMMAND_STRING_LENGTH + 3];
		memset(szText, 0, sizeof(szText));
		CreateThread(0, 0, Thread, 0, 0, 0);
		while (true)
		{
			//cout << "send - ";
			cin.getline(szText, sizeof(szText));
			bool isHavingNULLTerminator = false;

			if (isBase64Encoded)
			{
				char szTmp[128];
				strcpy(szTmp, szText);
				if (strlen(szTmp) > sizeof(szTmp))
					szTmp[127] = 0;
				base64(szText, szTmp, strlen(szTmp)*sizeof(szTmp[0]));
			}
			
			for (int i = 0; i < sizeof(szText)-1; i++)
			{
				if (szText[i] == 0)
				{
					szText[i] = '\r';
					szText[i + 1] = '\n';
					isHavingNULLTerminator = true;
					break;
				}
			}

			if (!isHavingNULLTerminator)
			{
				szText[MAX_SMTP_COMMAND_STRING_LENGTH] = '\r';
				szText[MAX_SMTP_COMMAND_STRING_LENGTH + 1] = '\n';
				szText[MAX_SMTP_COMMAND_STRING_LENGTH + 2] = 0;
				cout << "error - Your message or command is too large.";
				cout << "512 characters will be send on SMTP server." << endl;
			}

			BIO_write(bio, szText, strlen(szText));
			if (!strcmp(szText, "QUIT\r\n")) 
				break;
			memset(szText, 0, sizeof(szText));
		}
	}

	return 0;
}
