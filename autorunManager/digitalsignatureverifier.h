#ifndef DIGITALSIGNATUREVERIFIER_H
#define DIGITALSIGNATUREVERIFIER_H

#include <QString>
#include <QDateTime>
#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <cryptuiapi.h>
#include <mscat.h>
#include <wincrypt.h>

// 定义 OID 常量（如果系统头文件中没有定义）
#ifndef szOID_RSA_MD5
#define szOID_RSA_MD5 "1.2.840.113549.1.1.4"
#endif
#ifndef szOID_RSA_SHA1
#define szOID_RSA_SHA1 "1.2.840.113549.1.1.5"
#endif
#ifndef szOID_RSA_SHA256
#define szOID_RSA_SHA256 "1.2.840.113549.1.1.11"
#endif
#ifndef szOID_RSA_SHA384
#define szOID_RSA_SHA384 "1.2.840.113549.1.1.12"
#endif
#ifndef szOID_RSA_SHA512
#define szOID_RSA_SHA512 "1.2.840.113549.1.1.13"
#endif
#ifndef szOID_RSA_RSA
#define szOID_RSA_RSA "1.2.840.113549.1.1.1"
#endif
#ifndef szOID_X957_DSA
#define szOID_X957_DSA "1.2.840.10040.4.1"
#endif
#ifndef szOID_ECC_PUBLIC_KEY
#define szOID_ECC_PUBLIC_KEY "1.2.840.10045.2.1"
#endif

struct SignatureInfo {
    bool isValid = false;
    bool isEmbedded = false;
    bool isCatalog = false;
    QString status;
    QString signer;
    QString issuer;
    QDateTime signTime;
    QDateTime timeStamp;
    QString algorithm;
    QString catalogFile;
    QString errorDetails;
};

class DigitalSignatureVerifier {
public:
    DigitalSignatureVerifier();
    ~DigitalSignatureVerifier();

    SignatureInfo verifySignature(const QString& filePath);
    QString getSignatureDetails(const QString& filePath);

private:
    SignatureInfo verifyEmbeddedSignature(const QString& filePath);
    SignatureInfo verifyCatalogSignature(const QString& filePath);
    SignatureInfo getSignatureInfoFromContext(HCERTSTORE hStore, HCRYPTMSG hMsg);
    QString getVerificationStatus(LONG result);
    QString getAlgorithmNameFromOID(LPSTR oid); // 添加这行声明
    QDateTime fileTimeToDateTime(const FILETIME& fileTime);
    QString getCertName(PCCERT_CONTEXT pCertContext, DWORD type);
    bool getFileHash(const QString& filePath, ALG_ID algorithm, QByteArray& hash);
    HCATINFO findCatalogForFile(HCATADMIN hCatAdmin, const QByteArray& hash);
};

#endif // DIGITALSIGNATUREVERIFIER_H
