#include "stdafx.h"
#include <direct.h>
#include <conio.h>

void ErrorExit(char *lpszFunction) 
{ 
    // TCHAR szBuf[80]; 
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

	printf("%s failed with error 0x%lx: %S\nExiting\n", lpszFunction, dw, lpMsgBuf); 
	while (!_kbhit()) ;
 
    LocalFree(lpMsgBuf);
    ExitProcess(dw); 
}

void ReadPFXFile(LPCWSTR fileName, CRYPT_DATA_BLOB *pPFX)
{
	HANDLE hCertFile = NULL;
	DWORD cbRead = 0;
	DWORD dwFileSize = 0, dwFileSizeHi = 0;

	hCertFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hCertFile == INVALID_HANDLE_VALUE)
	{
		char buf[1024];
		printf("File not found: %S in %s\n", fileName, _getcwd(buf, 1024));
		ExitProcess(1);
	}
	dwFileSize = GetFileSize(hCertFile, &dwFileSizeHi);
	pPFX->pbData = (BYTE *) CryptMemAlloc(dwFileSize*sizeof(BYTE));
	pPFX->cbData = dwFileSize;

	ReadFile(hCertFile, pPFX->pbData, pPFX->cbData, &cbRead, NULL);
	CloseHandle(hCertFile);
}

void GetPrivateKey(CRYPT_DATA_BLOB pPFX, LPCWSTR szPassword, HCRYPTPROV *hCPContext, PCRYPT_KEY_PROV_INFO *Info)
{
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT hCertContext = NULL;
	DWORD dwKeySpec = AT_SIGNATURE;
	BOOL bFreeCertKey = TRUE;

	DWORD InfoSize = 0L;

	hCertStore = PFXImportCertStore(&pPFX, szPassword, CRYPT_EXPORTABLE);
	if (!hCertStore)
		ErrorExit("PFXImportCertStore");
	hCertContext = CertEnumCertificatesInStore(hCertStore, NULL);
	if (!hCertContext)
		ErrorExit("CertEnumCertificatesInStore");
	if (!CryptAcquireCertificatePrivateKey(hCertContext, 0, NULL, hCPContext, &dwKeySpec, &bFreeCertKey))
		ErrorExit("CryptAcquireCertificatePrivateKey");
	if (!CertGetCertificateContextProperty(hCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &InfoSize))
		ErrorExit("CertGetCertificateContextProperty (Get Size)");
	*Info = (PCRYPT_KEY_PROV_INFO) CryptMemAlloc(sizeof(BYTE) * InfoSize);
	if (!CertGetCertificateContextProperty(hCertContext, CERT_KEY_PROV_INFO_PROP_ID, *Info, &InfoSize))
		ErrorExit("CertGetCertificateContextProperty");
	// CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);		Why force?
	CertCloseStore(hCertStore, 0);
}

void PrintContainerName(HCRYPTPROV hCPContext)
{
	DWORD containerNameLen = 0;
	CHAR *szContainerName = NULL;

	if (!CryptGetProvParam(hCPContext, PP_CONTAINER, NULL, &containerNameLen, 0))
		ErrorExit("CryptGetProvParam (Get Size)");
	szContainerName = (CHAR *)CryptMemAlloc(sizeof(BYTE)*containerNameLen);
	if (!CryptGetProvParam(hCPContext, PP_CONTAINER, (BYTE *)szContainerName, &containerNameLen, 0))
		ErrorExit("CryptGetProvParam");
	printf("Certificate's container name is: %s [%d]\n", szContainerName, containerNameLen);
	CryptMemFree(szContainerName);
}

void MakeNewCert(HCRYPTPROV hCPContext, LPCWSTR szCertName, LPCWSTR szPassword, CRYPT_DATA_BLOB *pPFX, CRYPT_KEY_PROV_INFO Info)
{
	CERT_NAME_BLOB certNameBlob = {0,NULL};
	PCCERT_CONTEXT hCertContext = NULL;
	SYSTEMTIME certExpireDate;
	HCERTSTORE hTempStore = NULL;

	if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szCertName, CERT_OID_NAME_STR, NULL, NULL, &certNameBlob.cbData, NULL))
		ErrorExit("CertStrToName");
	certNameBlob.pbData = (BYTE *)CryptMemAlloc(sizeof(BYTE) * certNameBlob.cbData);
	if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szCertName, CERT_OID_NAME_STR, NULL, certNameBlob.pbData, &certNameBlob.cbData, NULL))
		ErrorExit("CertStrToName2");
	WCHAR buffer[1024];
	DWORD d;
	if ( d = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &certNameBlob, CERT_X500_NAME_STR, buffer, 1024 * sizeof(WCHAR)))
		printf("CertNameToStr: %S [%ld]\n", buffer, d);


	GetSystemTime(&certExpireDate);
	certExpireDate.wYear += 105;

	// hCertContext = CertCreateSelfSignCertificate(hCPContext, &certNameBlob, 0, NULL, NULL, NULL, &certExpireDate, NULL);
	hCertContext = CertCreateSelfSignCertificate(hCPContext, &certNameBlob, 0, &Info, NULL, NULL, &certExpireDate, NULL);
	if (!hCertContext)
		ErrorExit("CertCreateSelfSignCertificate");
	hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, 0);
	if (!hTempStore)
		ErrorExit("CertOpenStore");
	if (!CertAddCertificateContextToStore(hTempStore, hCertContext, CERT_STORE_ADD_NEW, NULL))
		ErrorExit("CertAddCertificateContextToStore");
	if (!PFXExportCertStoreEx(hTempStore, pPFX, szPassword, NULL, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
		ErrorExit("PFXExportCertStoreEx");
	pPFX->pbData = (BYTE *)CryptMemAlloc(sizeof(BYTE)*pPFX->cbData);
	if (!PFXExportCertStoreEx(hTempStore, pPFX, szPassword, NULL, EXPORT_PRIVATE_KEYS))
		ErrorExit("PFXExportCertStoreEx2");

	CryptMemFree(certNameBlob.pbData);
	// CertCloseStore(hTempStore, CERT_CLOSE_STORE_FORCE_FLAG);
	CertCloseStore(hTempStore, 0);
	CertFreeCertificateContext(hCertContext);
}

void WritePFX(CRYPT_DATA_BLOB pPFX, LPCWSTR szOutputFile)
{
	HANDLE hOutputFile = NULL;
	DWORD cbWritten = 0;

	hOutputFile = CreateFile(szOutputFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE)
		ErrorExit("CreateFile");
	if (!WriteFile(hOutputFile, pPFX.pbData, pPFX.cbData, &cbWritten, NULL))
		ErrorExit("WriteFile");
	CloseHandle(hOutputFile);
}


int _tmain(int argc, _TCHAR* argv[])
{
	LPCWSTR szCertFileName = NULL;

	CRYPT_DATA_BLOB pPFX;
	LPCWSTR szPassword = NULL;
	HCRYPTPROV hCPContext = NULL;

	LPCWSTR szCertName = L"CN=NewCert";
	CRYPT_DATA_BLOB pPfxOutputBlob = {0,NULL};
	LPCWSTR szOutFile = NULL;

	PCRYPT_KEY_PROV_INFO provInfo;

	// Parse the command line.
	if(argc == 1)
	{
		printf("renewcert <PFX File> <new cert filename> <new cert friendly name> [optional]<password>\n");
		printf("Example: renewcert oldcert.pfx newcert.pfx \"CN=MyNewCert\" MySuperSecretPassword");
		return 0;
	}

	if(argc >= 2)
		szCertFileName = argv[1];
	if(argc >= 5)
		szPassword = argv[4];
	// Uncomment this block to add <new cert filename> and <new cert friendly name> as parameters
	// NOTE: <new cert friendly name> must be of format "CN=<name>"
	if(argc >= 3)
		szOutFile = argv[2];
	if(argc >= 4)
		szCertName = argv[3];

	ReadPFXFile(szCertFileName, &pPFX);

	GetPrivateKey(pPFX, szPassword, &hCPContext, &provInfo);

	PrintContainerName(hCPContext);

	// Uncomment this section to make a new PFX rather than just printing the container name.
	// Make sure you also uncomment the command line parameter section above.
	MakeNewCert(hCPContext, szCertName, szPassword, &pPfxOutputBlob, *provInfo);
	WritePFX(pPfxOutputBlob, szOutFile);

	char buffer[1024];
	printf("Created File: %s\\%S\n", _getcwd(buffer, sizeof(buffer)), szOutFile);
	printf("Press any key to exit.\n");
	while (!_kbhit()) ;

	// Clean up.
	CryptReleaseContext(hCPContext, 0);
	CryptMemFree(pPfxOutputBlob.pbData);
	CryptMemFree(pPFX.pbData);
	return 0;
}