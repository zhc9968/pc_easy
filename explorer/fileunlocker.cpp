#include "FileUnlocker.h"
#include <QDebug>
#include <QFileInfo>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <memory>

FileUnlocker::FileUnlocker() {
    enableDebugPrivilege();
}

FileUnlocker::~FileUnlocker() {
}

QVector<ProcessInfo> FileUnlocker::getLockingProcesses(const QString& filePath) {
    m_lastError.clear();
    QVector<ProcessInfo> result;

    qDebug() << "检测文件占用:" << filePath;

    // 1. 首先使用重启管理器快速检测
    QVector<ProcessInfo> restartManagerProcesses = getLockingProcessesByRestartManager(filePath);

    if (!restartManagerProcesses.isEmpty()) {
        qDebug() << "重启管理器找到" << restartManagerProcesses.size() << "个占用进程";

        // 2. 只有重启管理器找到了进程，才使用内核对象遍历补充句柄信息
        result = supplementHandleInfo(restartManagerProcesses, filePath);

        // 检查是否有句柄信息
        bool hasHandleInfo = false;
        for (const auto& process : result) {
            if (process.handleValue != 0) {
                hasHandleInfo = true;
                break;
            }
        }
        qDebug() << restartManagerProcesses[0].processPath;
        if (!hasHandleInfo) {
            qDebug() << "重启管理器找到进程，但内核对象遍历未找到句柄信息";
        }
    } else {
        qDebug() << "重启管理器未找到占用进程，直接返回空列表";
        // 不再使用内核对象遍历
        result.clear();
    }

    // 设置状态信息
    for (auto& process : result) {
        if (process.handleValue == 0) {
            process.status = "占用中(重启管理器检测)";
        } else {
            process.status = "占用中(有句柄信息)";
        }
    }

    qDebug() << "最终检测到" << result.size() << "个占用进程";
    return result;
}

QVector<ProcessInfo> FileUnlocker::supplementHandleInfo(const QVector<ProcessInfo>& restartManagerProcesses, const QString& filePath) {
    QVector<ProcessInfo> result = restartManagerProcesses;

    if (restartManagerProcesses.isEmpty()) {
        return result;
    }

    // 获取目标文件的唯一标识
    FileIdentifier targetId = getFileIdentifier(filePath);
    if (!targetId.isValid) {
        m_lastError = "无法获取目标文件的唯一标识";
        qDebug() << m_lastError;
        return result;
    }

    // 定义系统句柄信息结构
    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

    // 获取NTDLL函数指针
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        m_lastError = "无法加载ntdll.dll";
        return result;
    }

    typedef NTSTATUS(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        m_lastError = "无法获取NtQuerySystemInformation函数";
        return result;
    }

    // 获取系统句柄信息
    ULONG bufferSize = 1024 * 1024;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    for (int attempt = 0; attempt < 3; attempt++) {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
        if (!handleInfo) {
            m_lastError = "内存分配失败";
            return result;
        }

        ULONG returnLength = 0;
        status = NtQuerySystemInformation(64, handleInfo, bufferSize, &returnLength);

        if (status == STATUS_SUCCESS) {
            qDebug() << "成功获取句柄信息，系统中共有" << handleInfo->NumberOfHandles << "个句柄";
            break;
        } else if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength + 4096;
            free(handleInfo);
            handleInfo = nullptr;
        } else {
            m_lastError = QString("NtQuerySystemInformation失败: 0x%1").arg(status, 0, 16);
            free(handleInfo);
            return result;
        }
    }

    if (!handleInfo || status != STATUS_SUCCESS) {
        if (handleInfo) free(handleInfo);
        return result;
    }

    // 创建进程ID集合，用于快速查找
    QSet<DWORD> targetProcessIds;
    for (const auto& process : restartManagerProcesses) {
        targetProcessIds.insert(process.processId);
        qDebug() << "目标进程ID:" << process.processId << "名称:" << process.processName;
    }

    // 创建进程句柄缓存
    QMap<DWORD, HANDLE> processHandleCache;
    int foundHandleCount = 0;

    // 遍历所有句柄，只为目标进程补充句柄信息
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = handleInfo->Handles[i];
        DWORD processId = static_cast<DWORD>(handle.UniqueProcessId);

        // 只处理目标进程的句柄
        if (!targetProcessIds.contains(processId)) {
            continue;
        }

        // 跳过非文件对象（类型索引42）
        if (handle.ObjectTypeIndex != 42) {
            continue;
        }

        // 获取或创建进程句柄
        HANDLE hProcess = nullptr;
        if (processHandleCache.contains(processId)) {
            hProcess = processHandleCache[processId];
        } else {
            hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (hProcess) {
                processHandleCache.insert(processId, hProcess);
            } else {
                qDebug() << "无法打开进程" << processId << "，错误:" << GetLastError();
                continue;
            }
        }

        // 复制句柄到当前进程
        HANDLE hDupHandle = NULL;
        if (!DuplicateHandle(hProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(),
                             &hDupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            qDebug() << "无法复制进程" << processId << "的句柄，错误:" << GetLastError();
            continue;
        }

        // 检查是否为磁盘文件
        DWORD fileType = GetFileType(hDupHandle);
        if (fileType != FILE_TYPE_DISK) {
            CloseHandle(hDupHandle);
            continue;
        }

        // 获取文件信息
        BY_HANDLE_FILE_INFORMATION fileInfo;
        if (!GetFileInformationByHandle(hDupHandle, &fileInfo)) {
            CloseHandle(hDupHandle);
            continue;
        }

        // 比较文件标识
        ULONGLONG fileIndex = ((ULONGLONG)fileInfo.nFileIndexHigh << 32) | fileInfo.nFileIndexLow;
        if (fileInfo.dwVolumeSerialNumber == targetId.volumeSerial && fileIndex == targetId.fileIndex) {
            // 找到匹配的句柄，更新对应的进程信息
            for (auto& process : result) {
                if (process.processId == processId) {
                    // 只有当当前句柄值为0时才更新（避免覆盖已有句柄信息）
                    if (process.handleValue == 0) {
                        process.handleValue = static_cast<ULONG_PTR>(handle.HandleValue);
                        foundHandleCount++;
                        qDebug() << "为进程" << processId << "找到句柄: 0x" << QString::number(handle.HandleValue, 16);
                    }

                    // 在这里获取进程路径！！！
                    if (process.processPath.isEmpty()) {
                        WCHAR processPath[MAX_PATH] = {0};
                        DWORD pathSize = MAX_PATH;

                        // 使用QueryFullProcessImageNameW获取完整进程路径
                        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
                            process.processPath = QString::fromWCharArray(processPath);
                            qDebug() << "为进程" << processId << "获取进程路径:" << process.processPath;
                        } else {
                            // 备用方法：使用GetProcessImageFileNameW
                            if (GetProcessImageFileNameW(hProcess, processPath, MAX_PATH)) {
                                process.processPath = QString::fromWCharArray(processPath);
                                qDebug() << "使用备用方法获取进程路径:" << process.processPath;
                            } else {
                                qDebug() << "无法获取进程" << processId << "的路径，错误:" << GetLastError();
                            }
                        }
                    }
                    break;
                }
            }
        }

        CloseHandle(hDupHandle);
    }

    // 清理资源
    for (auto handle : processHandleCache) {
        CloseHandle(handle);
    }
    free(handleInfo);

    qDebug() << "内核对象遍历为" << foundHandleCount << "个进程补充了句柄信息";
    return result;
}

QVector<ProcessInfo> FileUnlocker::getLockingProcessesByRestartManager(const QString& filePath) {
    QVector<ProcessInfo> result;
    m_lastError.clear();

    DWORD dwSession;
    WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = {0};

    // 启动重启管理器会话
    DWORD dwError = RmStartSession(&dwSession, 0, szSessionKey);
    if (dwError != ERROR_SUCCESS) {
        qDebug() << "RmStartSession失败，错误代码:" << dwError;
        return result;
    }

    // 注册要检查的文件资源
    std::wstring widePath = filePath.toStdWString();
    LPCWSTR rgsFiles[] = { widePath.c_str() };

    dwError = RmRegisterResources(dwSession, 1, rgsFiles, 0, NULL, 0, NULL);
    if (dwError != ERROR_SUCCESS) {
        qDebug() << "RmRegisterResources失败，错误代码:" << dwError;
        RmEndSession(dwSession);
        return result;
    }

    // 获取占用文件的进程列表
    DWORD dwReason;
    UINT nProcInfoNeeded = 0;
    UINT nProcInfo = 0;

    // 第一次调用获取所需缓冲区大小
    dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);

    if (dwError != ERROR_MORE_DATA && dwError != ERROR_SUCCESS) {
        qDebug() << "RmGetList第一次调用失败，错误代码:" << dwError;
        RmEndSession(dwSession);
        return result;
    }

    // 分配缓冲区
    std::vector<RM_PROCESS_INFO> processInfoBuffer(nProcInfoNeeded);
    nProcInfo = nProcInfoNeeded;

    dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, processInfoBuffer.data(), &dwReason);

    if (dwError == ERROR_SUCCESS) {
        for (UINT i = 0; i < nProcInfo; i++) {
            const RM_PROCESS_INFO& procInfo = processInfoBuffer[i];
            ProcessInfo info;
            info.processId = procInfo.Process.dwProcessId;
            info.filePath = filePath;
            info.handleValue = 0; // 重启管理器不提供句柄值，后续补充

            // 获取进程名称
            if (procInfo.strAppName[0] != L'\0') {
                info.processName = QString::fromWCharArray(procInfo.strAppName);
            } else {
                info.processPath = getProcessPath(info.processId);
                info.processName = getProcessNameFromPath(info.processPath);

                if (info.processName.isEmpty()) {
                    info.processName = QString("进程_%1").arg(info.processId);
                }
            }

            result.append(info);
            qDebug() << "重启管理器找到进程:" << info.processId << info.processName;
        }
    } else {
        qDebug() << "RmGetList第二次调用失败，错误代码:" << dwError;
    }

    RmEndSession(dwSession);
    return result;
}

QVector<ProcessInfo> FileUnlocker::getLockingProcessesByKernelObjects(const QString& filePath) {
    QVector<ProcessInfo> result;
    m_lastError.clear();

    qDebug() << "使用内核对象遍历检测文件占用:" << filePath;

    // 获取目标文件的唯一标识
    FileIdentifier targetId = getFileIdentifier(filePath);
    if (!targetId.isValid) {
        m_lastError = "无法获取目标文件的唯一标识";
        qDebug() << m_lastError;
        return result;
    }

    // 定义系统句柄信息结构
    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

    // 获取NTDLL函数指针
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        DWORD error = GetLastError();
        m_lastError = QString("无法加载ntdll.dll，错误代码: %1").arg(error);
        qDebug() << m_lastError;
        return result;
    }

    typedef NTSTATUS(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        DWORD error = GetLastError();
        m_lastError = QString("无法获取NtQuerySystemInformation函数，错误代码: %1").arg(error);
        qDebug() << m_lastError;
        return result;
    }

    // 尝试使用 SystemExtendedHandleInformation (64)
    ULONG bufferSize = 1024 * 1024; // 初始分配1MB
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    for (int attempt = 0; attempt < 3; attempt++) {
        if (handleInfo) {
            free(handleInfo);
            handleInfo = nullptr;
        }

        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
        if (!handleInfo) {
            m_lastError = "内存分配失败";
            qDebug() << m_lastError;
            return result;
        }

        ULONG returnLength = 0;
        status = NtQuerySystemInformation(64, handleInfo, bufferSize, &returnLength);

        if (status == STATUS_SUCCESS) {
            qDebug() << "成功获取句柄信息，找到" << handleInfo->NumberOfHandles << "个系统句柄";
            break;
        } else if (status == STATUS_INFO_LENGTH_MISMATCH) {
            qDebug() << "缓冲区大小不足，需要" << returnLength << "字节，当前" << bufferSize;
            bufferSize = returnLength + 4096; // 增加4KB额外空间
        } else {
            m_lastError = QString("NtQuerySystemInformation失败，状态: 0x%1").arg(status, 0, 16);
            qDebug() << m_lastError;
            free(handleInfo);
            handleInfo = nullptr;
            return result;
        }
    }

    if (!handleInfo || status != STATUS_SUCCESS) {
        m_lastError = QString("无法获取系统句柄信息，最终状态: 0x%1").arg(status, 0, 16);
        qDebug() << m_lastError;
        if (handleInfo) free(handleInfo);
        return result;
    }

    // 创建进程句柄缓存
    QMap<DWORD, HANDLE> processHandleCache;
    QMap<DWORD, ProcessInfo> processInfoCache;

    // 遍历所有句柄
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = handleInfo->Handles[i];
        DWORD processId = static_cast<DWORD>(handle.UniqueProcessId);

        // 跳过系统进程和无效进程ID
        if (processId == 0 || processId == 4 || processId > 0xFFFF) {
            continue;
        }

        // 跳过非文件对象（类型索引42）
        if (handle.ObjectTypeIndex != 42) continue;

        // 获取或创建进程句柄
        HANDLE hProcess = nullptr;
        if (processHandleCache.contains(processId)) {
            hProcess = processHandleCache[processId];
        } else {
            hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (hProcess) {
                processHandleCache.insert(processId, hProcess);
            } else {
                // 无法打开进程，跳过
                continue;
            }
        }

        // 复制句柄到当前进程
        HANDLE hDupHandle = NULL;
        if (!DuplicateHandle(hProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(),
                             &hDupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            // 无法复制句柄，跳过
            continue;
        }

        // 检查句柄类型是否为磁盘文件
        DWORD fileType = GetFileType(hDupHandle);
        if (fileType != FILE_TYPE_DISK) {
            CloseHandle(hDupHandle);
            continue;
        }

        // 获取文件信息
        BY_HANDLE_FILE_INFORMATION fileInfo;
        if (!GetFileInformationByHandle(hDupHandle, &fileInfo)) {
            CloseHandle(hDupHandle);
            continue;
        }

        // 计算文件唯一标识
        ULONGLONG fileIndex = ((ULONGLONG)fileInfo.nFileIndexHigh << 32) | fileInfo.nFileIndexLow;
        DWORD volumeSerial = fileInfo.dwVolumeSerialNumber;

        // 比较文件标识
        if (volumeSerial == targetId.volumeSerial && fileIndex == targetId.fileIndex) {
            // 获取或创建进程信息
            ProcessInfo info;
            if (processInfoCache.contains(processId)) {
                info = processInfoCache[processId];
            } else {
                info.processId = processId;
                info.processName = getProcessName(processId);
                info.processPath = getProcessPath(processId);
                processInfoCache.insert(processId, info);
            }

            info.filePath = filePath;
            info.handleValue = static_cast<ULONG_PTR>(handle.HandleValue);
            result.append(info);

            qDebug() << "找到占用文件的进程 - PID:" << info.processId
                     << "名称:" << info.processName
                     << "句柄:" << QString("0x%1").arg(info.handleValue, 0, 16);
        }

        CloseHandle(hDupHandle);
    }

    // 清理资源
    for (auto handle : processHandleCache) {
        CloseHandle(handle);
    }
    free(handleInfo);

    qDebug() << "内核对象遍历检测到" << result.size() << "个占用进程";
    return result;
}

bool FileUnlocker::unlockFile(const QString& filePath) {
    m_lastError.clear();

    QVector<ProcessInfo> processes = getLockingProcesses(filePath);
    if (processes.isEmpty()) {
        m_lastError = "没有找到占用文件的进程";
        return false;
    }

    int successCount = 0;
    for (const ProcessInfo& info : processes) {
        if (terminateProcess(info.processId)) {
            successCount++;
            qDebug() << "成功结束进程:" << info.processId << info.processName;
        } else {
            qDebug() << "结束进程失败:" << info.processId << m_lastError;
        }

        // 短暂延迟
        Sleep(100);
    }

    if (successCount > 0) {
        m_lastError = QString("成功解锁文件，结束了%1个进程").arg(successCount);
        return true;
    } else {
        m_lastError = "无法结束任何占用进程";
        return false;
    }
}

bool FileUnlocker::closeSpecificHandle(DWORD processId, ULONG_PTR handle) {
    return closeRemoteHandle(processId, handle);
}

bool FileUnlocker::terminateProcess(DWORD processId) {
    if (processId == 0 || processId == 4) { // 跳过系统和空闲进程
        m_lastError = "无法终止系统进程";
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (!hProcess) {
        m_lastError = QString("无法打开进程%1").arg(processId);
        return false;
    }

    BOOL result = TerminateProcess(hProcess, 0);
    DWORD error = GetLastError();
    CloseHandle(hProcess);

    if (result) {
        return true;
    } else {
        m_lastError = QString("终止进程失败，错误代码: %1").arg(error);
        return false;
    }
}

bool FileUnlocker::unlockAllHandles(const QVector<ProcessInfo>& processes) {
    int successCount = 0;
    int totalHandles = 0;

    for (const ProcessInfo& info : processes) {
        if (info.handleValue != 0) {
            totalHandles++;
            if (closeRemoteHandle(info.processId, info.handleValue)) {
                successCount++;
                qDebug() << "成功关闭句柄 - 进程:" << info.processId
                         << "句柄:" << QString("0x%1").arg(info.handleValue, 0, 16);
            } else {
                qDebug() << "关闭句柄失败 - 进程:" << info.processId
                         << "句柄:" << QString("0x%1").arg(info.handleValue, 0, 16)
                         << "错误:" << m_lastError;
            }
        }
    }

    if (totalHandles == 0) {
        m_lastError = "没有找到可关闭的句柄";
        return false;
    }

    if (successCount > 0) {
        m_lastError = QString("成功关闭%1/%2个句柄").arg(successCount).arg(totalHandles);
        return true;
    } else {
        m_lastError = QString("无法关闭任何句柄（尝试关闭%1个）").arg(totalHandles);
        return false;
    }
}

bool FileUnlocker::closeRemoteHandle(DWORD processId, ULONG_PTR handle) {
    if (processId == 0 || processId == 4) {
        m_lastError = "无法关闭系统进程的句柄";
        return false;
    }

    if (handle == 0) {
        m_lastError = "无效的句柄值";
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);
    if (!hProcess) {
        DWORD error = GetLastError();
        m_lastError = QString("无法打开进程%1，错误代码: %2").arg(processId).arg(error);
        return false;
    }

    // 复制句柄到当前进程并使用DUPLICATE_CLOSE_SOURCE关闭源句柄
    HANDLE hDupHandle = NULL;
    if (!DuplicateHandle(hProcess, (HANDLE)handle, GetCurrentProcess(),
                         &hDupHandle, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
        DWORD error = GetLastError();
        m_lastError = QString("复制句柄失败，错误代码: %1").arg(error);
        CloseHandle(hProcess);
        return false;
    }

    // 关闭复制的句柄
    CloseHandle(hDupHandle);
    CloseHandle(hProcess);

    qDebug() << "成功关闭进程" << processId << "的句柄" << QString("0x%1").arg(handle, 0, 16);
    return true;
}

bool FileUnlocker::isFileLocked(const QString& filePath) {
    // 方法1: 尝试以独占方式打开
    HANDLE hFile = CreateFileW(
        filePath.toStdWString().c_str(),
        GENERIC_READ,
        0,  // 无共享
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_SHARING_VIOLATION) {
            return true;
        }
        return false;
    }

    CloseHandle(hFile);

    // 方法2: 使用重启管理器验证
    return !getLockingProcesses(filePath).isEmpty();
}

QString FileUnlocker::getProcessPath(DWORD processId) {
    if (processId == 0) return QString();

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return QString();

    WCHAR processPath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;

    if (GetProcessImageFileNameW(hProcess, processPath, size)) {
        CloseHandle(hProcess);
        return QString::fromWCharArray(processPath);
    }

    CloseHandle(hProcess);
    return QString();
}

QString FileUnlocker::getProcessNameFromPath(const QString& processPath) {
    if (processPath.isEmpty()) return QString();

    QFileInfo fileInfo(processPath);
    return fileInfo.fileName();
}

QString FileUnlocker::getProcessName(DWORD processId) {
    if (processId == 0) return QString();

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return QString("未知进程");

    WCHAR processName[MAX_PATH] = {0};
    DWORD size = MAX_PATH;

    if (GetProcessImageFileNameW(hProcess, processName, size)) {
        CloseHandle(hProcess);
        QString fullPath = QString::fromWCharArray(processName);
        return getProcessNameFromPath(fullPath);
    }

    CloseHandle(hProcess);
    return QString("进程_%1").arg(processId);
}

bool FileUnlocker::enableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

FileUnlocker::FileIdentifier FileUnlocker::getFileIdentifier(const QString& filePath) {
    FileIdentifier id;

    HANDLE hFile = CreateFileW(
        filePath.toStdWString().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        NULL
        );

    if (hFile != INVALID_HANDLE_VALUE) {
        BY_HANDLE_FILE_INFORMATION fileInfo;
        if (GetFileInformationByHandle(hFile, &fileInfo)) {
            id.volumeSerial = fileInfo.dwVolumeSerialNumber;
            id.fileIndex = ((ULONGLONG)fileInfo.nFileIndexHigh << 32) | fileInfo.nFileIndexLow;
            id.isValid = true;
        }
        CloseHandle(hFile);
    }

    return id;
}
