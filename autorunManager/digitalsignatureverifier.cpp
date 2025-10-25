#include "DigitalSignatureVerifier.h"
#include <QFileInfo>
#include <QDebug>

DigitalSignatureVerifier::DigitalSignatureVerifier() {
    // 初始化加密API
    CryptAcquireContext(NULL, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
}

DigitalSignatureVerifier::~DigitalSignatureVerifier() {
    // 清理资源
}

SignatureInfo DigitalSignatureVerifier::verifySignature(const QString& filePath) {
    SignatureInfo result;

    if (filePath.isEmpty()) {
        result.status = "无文件路径";
        return result;
    }

    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        result.status = "文件不存在";
        return result;
    }

    // 首先尝试嵌入式签名验证
    result = verifyEmbeddedSignature(filePath);

    // 如果嵌入式签名验证失败或无签名，尝试目录签名验证
    if (!result.isValid && result.status.contains("无数字签名")) {
        SignatureInfo catalogResult = verifyCatalogSignature(filePath);
        if (catalogResult.isValid) {
            result = catalogResult;
        }
    }

    return result;
}

QString DigitalSignatureVerifier::getSignatureDetails(const QString& filePath) {
    SignatureInfo info = verifySignature(filePath);

    QString details;
    details += QString("签名状态: %1\n").arg(info.status);
    details += QString("签名类型: %1\n").arg(info.isEmbedded ? "嵌入式签名" :
                                                 info.isCatalog ? "目录签名" : "无签名");
    details += QString("签名者: %1\n").arg(info.signer.isEmpty() ? "未知" : info.signer);
    details += QString("颁发者: %1\n").arg(info.issuer.isEmpty() ? "未知" : info.issuer);

    if (info.signTime.isValid()) {
        details += QString("签名时间: %1\n").arg(info.signTime.toString("yyyy-MM-dd hh:mm:ss"));
    }

    if (info.timeStamp.isValid()) {
        details += QString("时间戳: %1\n").arg(info.timeStamp.toString("yyyy-MM-dd hh:mm:ss"));
    }

    details += QString("算法: %1\n").arg(info.algorithm.isEmpty() ? "未知" : info.algorithm);

    if (!info.catalogFile.isEmpty()) {
        details += QString("目录文件: %1\n").arg(info.catalogFile);
    }

    if (!info.errorDetails.isEmpty()) {
        details += QString("错误详情: %1\n").arg(info.errorDetails);
    }

    return details;
}

SignatureInfo DigitalSignatureVerifier::verifyEmbeddedSignature(const QString& filePath) {
    SignatureInfo result;
    result.isEmbedded = true;

    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.toStdWString().c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA trustData = {0};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;  // 检查整个证书链
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // 设置验证时间戳
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG verifyResult = WinVerifyTrust(NULL, &action, &trustData);

    result.status = getVerificationStatus(verifyResult);
    result.isValid = (verifyResult == ERROR_SUCCESS);

    // 获取签名详细信息
    if (verifyResult == ERROR_SUCCESS || verifyResult == TRUST_E_EXPLICIT_DISTRUST) {
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;

        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                             filePath.toStdWString().c_str(),
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY,
                             0, NULL, NULL, NULL, &hStore, &hMsg, NULL)) {
            SignatureInfo detailedInfo = getSignatureInfoFromContext(hStore, hMsg);

            // 合并信息
            result.signer = detailedInfo.signer;
            result.issuer = detailedInfo.issuer;
            result.signTime = detailedInfo.signTime;
            result.timeStamp = detailedInfo.timeStamp;
            result.algorithm = detailedInfo.algorithm;

            if (hMsg) CryptMsgClose(hMsg);
            if (hStore) CertCloseStore(hStore, 0);
        }
    }

    // 清理状态数据
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &trustData);

    return result;
}

SignatureInfo DigitalSignatureVerifier::verifyCatalogSignature(const QString& filePath) {
    SignatureInfo result;
    result.isCatalog = true;

    // 计算文件哈希
    QByteArray hash;
    if (!getFileHash(filePath, CALG_SHA1, hash)) {
        result.status = "无法计算文件哈希";
        return result;
    }

    HCATADMIN hCatAdmin = NULL;
    HCATINFO hCatInfo = NULL;

    // 初始化目录管理员
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
        result.status = "无法初始化目录管理员";
        return result;
    }

    // 查找匹配的目录
    hCatInfo = findCatalogForFile(hCatAdmin, hash);
    if (!hCatInfo) {
        result.status = "无目录签名";
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return result;
    }

    // 验证目录签名
    CATALOG_INFO catalogInfo = {0};
    catalogInfo.cbStruct = sizeof(catalogInfo);

    if (CryptCATCatalogInfoFromContext(hCatInfo, &catalogInfo, 0)) {
        WINTRUST_CATALOG_INFO wtCatalogInfo = {0};
        wtCatalogInfo.cbStruct = sizeof(wtCatalogInfo);
        wtCatalogInfo.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
        wtCatalogInfo.pcwszMemberFilePath = filePath.toStdWString().c_str();
        wtCatalogInfo.hMemberFile = NULL;
        wtCatalogInfo.pbCalculatedFileHash = (BYTE*)hash.data();
        wtCatalogInfo.cbCalculatedFileHash = hash.size();
        wtCatalogInfo.pcCatalogContext = NULL;

        WINTRUST_DATA trustData = {0};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
        trustData.pCatalog = &wtCatalogInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG verifyResult = WinVerifyTrust(NULL, &action, &trustData);

        result.status = getVerificationStatus(verifyResult);
        result.isValid = (verifyResult == ERROR_SUCCESS);
        result.catalogFile = QString::fromWCharArray(catalogInfo.wszCatalogFile);

        // 获取目录签名详细信息
        if (verifyResult == ERROR_SUCCESS || verifyResult == TRUST_E_EXPLICIT_DISTRUST) {
            HCERTSTORE hStore = NULL;
            HCRYPTMSG hMsg = NULL;

            if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                 catalogInfo.wszCatalogFile,
                                 CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                 CERT_QUERY_FORMAT_FLAG_BINARY,
                                 0, NULL, NULL, NULL, &hStore, &hMsg, NULL)) {
                SignatureInfo detailedInfo = getSignatureInfoFromContext(hStore, hMsg);

                result.signer = detailedInfo.signer;
                result.issuer = detailedInfo.issuer;
                result.signTime = detailedInfo.signTime;
                result.timeStamp = detailedInfo.timeStamp;
                result.algorithm = detailedInfo.algorithm;

                if (hMsg) CryptMsgClose(hMsg);
                if (hStore) CertCloseStore(hStore, 0);
            }
        }

        // 清理状态数据
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &trustData);
    }

    if (hCatInfo) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    if (hCatAdmin) CryptCATAdminReleaseContext(hCatAdmin, 0);

    return result;
}

SignatureInfo DigitalSignatureVerifier::getSignatureInfoFromContext(HCERTSTORE hStore, HCRYPTMSG hMsg) {
    SignatureInfo info;

    if (!hMsg) return info;

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize)) {
        return info;
    }

    QByteArray signerInfoBuffer(signerInfoSize, 0);
    PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)signerInfoBuffer.data();

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize)) {
        return info;
    }

    // 获取签名者证书
    CERT_INFO certInfo = {0};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore,
                                                             X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                             0,
                                                             CERT_FIND_SUBJECT_CERT,
                                                             (PVOID)&certInfo,
                                                             NULL);

    if (pCertContext) {
        info.signer = getCertName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE);
        info.issuer = getCertName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE);

        // 修复：使用OID字符串而不是ALG_ID
        info.algorithm = getAlgorithmNameFromOID(pSignerInfo->HashAlgorithm.pszObjId);

        // 获取签名时间 - 使用正确的常量名称
        DWORD signerTimeSize = 0;
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, NULL, &signerTimeSize)) {
            QByteArray signerTimeBuffer(signerTimeSize, 0);
            PCRYPT_ATTRIBUTES pSignerTime = (PCRYPT_ATTRIBUTES)signerTimeBuffer.data();

            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, pSignerTime, &signerTimeSize)) {
                // 解析签名时间
                for (DWORD i = 0; i < pSignerTime->cAttr; i++) {
                    if (strcmp(pSignerTime->rgAttr[i].pszObjId, szOID_RSA_signingTime) == 0) {
                        if (pSignerTime->rgAttr[i].cValue > 0) {
                            // 解析时间戳
                            // 这里简化处理，实际需要解析ASN.1时间格式
                        }
                    }
                }
            }
        }

        // 获取时间戳（如果存在）
        DWORD counterSignerIndex = 0;
        DWORD counterSignerInfoSize = 0;

        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, counterSignerIndex,
                             NULL, &counterSignerInfoSize)) {
            // 解析计数器签名（时间戳）
        }

        CertFreeCertificateContext(pCertContext);
    }

    return info;
}

QString DigitalSignatureVerifier::getVerificationStatus(LONG result) {
    switch (result) {
    case ERROR_SUCCESS:
        return "有效签名";
    case TRUST_E_NOSIGNATURE:
        return "无数字签名";
    case TRUST_E_EXPLICIT_DISTRUST:
        return "签名被显式拒绝";
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        return "签名不受信任";
    case TRUST_E_BAD_DIGEST:
        return "文件已被修改";
    case CRYPT_E_SECURITY_SETTINGS:
        return "安全设置阻止验证签名";
    case CERT_E_EXPIRED:
        return "证书已过期";
    case CERT_E_VALIDITYPERIODNESTING:
        return "证书有效期嵌套错误";
    case CERT_E_REVOKED:
        return "证书已被吊销";
    case TRUST_E_COUNTER_SIGNER:
        return "计数器签名错误";
    default:
        return QString("签名验证失败 (错误代码: 0x%1)").arg(result, 8, 16, QLatin1Char('0'));
    }
}

// 新增函数：根据OID获取算法名称
QString DigitalSignatureVerifier::getAlgorithmNameFromOID(LPSTR oid) {
    if (strcmp(oid, szOID_RSA_MD5) == 0) return "MD5";
    if (strcmp(oid, szOID_RSA_SHA1) == 0) return "SHA1";
    if (strcmp(oid, szOID_RSA_SHA256) == 0) return "SHA256";
    if (strcmp(oid, szOID_RSA_SHA384) == 0) return "SHA384";
    if (strcmp(oid, szOID_RSA_SHA512) == 0) return "SHA512";
    if (strcmp(oid, szOID_RSA_RSA) == 0) return "RSA";
    if (strcmp(oid, szOID_X957_DSA) == 0) return "DSA";
    if (strcmp(oid, szOID_ECC_PUBLIC_KEY) == 0) return "ECC";
    return "未知算法";
}

QDateTime DigitalSignatureVerifier::fileTimeToDateTime(const FILETIME& fileTime) {
    ULARGE_INTEGER ull;
    ull.LowPart = fileTime.dwLowDateTime;
    ull.HighPart = fileTime.dwHighDateTime;

    QDateTime dateTime;
    dateTime.setMSecsSinceEpoch(ull.QuadPart / 10000 - 11644473600000LL);
    return dateTime;
}

QString DigitalSignatureVerifier::getCertName(PCCERT_CONTEXT pCertContext, DWORD type) {
    if (!pCertContext) return QString();

    DWORD size = CertGetNameStringW(pCertContext, type, 0, NULL, NULL, 0);
    if (size <= 1) return QString();

    QVector<wchar_t> buffer(size);
    CertGetNameStringW(pCertContext, type, 0, NULL, buffer.data(), size);

    return QString::fromWCharArray(buffer.data());
}

bool DigitalSignatureVerifier::getFileHash(const QString& filePath, ALG_ID algorithm, QByteArray& hash) {
    HANDLE hFile = CreateFileW(filePath.toStdWString().c_str(),
                               GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    bool success = false;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, algorithm, 0, 0, &hHash)) {
            BYTE buffer[4096];
            DWORD read = 0;

            while (ReadFile(hFile, buffer, sizeof(buffer), &read, NULL) && read > 0) {
                CryptHashData(hHash, buffer, read, 0);
            }

            DWORD hashSize = 0;
            DWORD hashSizeSize = sizeof(hashSize);
            if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeSize, 0)) {
                hash.resize(hashSize);
                if (CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hash.data(), &hashSize, 0)) {
                    success = true;
                }
            }

            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }

    CloseHandle(hFile);
    return success;
}

HCATINFO DigitalSignatureVerifier::findCatalogForFile(HCATADMIN hCatAdmin, const QByteArray& hash) {
    if (!hCatAdmin || hash.isEmpty()) return NULL;

    // 首先尝试SHA1哈希
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin,
                                                         (BYTE*)hash.data(),
                                                         hash.size(), 0, NULL);

    // 如果找不到，可以尝试其他哈希算法
    if (!hCatInfo) {
        // 这里可以添加对其他哈希算法的支持
    }

    return hCatInfo;
}
