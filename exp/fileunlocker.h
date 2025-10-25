#ifndef FILEUNLOCKER_H
#define FILEUNLOCKER_H

#include <QString>
#include <QVector>
#include <QSet>
#include <QMap>
#include <windows.h>
#include <restartmanager.h>
#include <QDir>
// 然后继续原有的代码
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#pragma comment(lib, "Rstrtmgr.lib")
#pragma comment(lib, "psapi.lib")

struct ProcessInfo {
    DWORD processId;
    QString processName;
    QString processPath;
    QString filePath;
    ULONG_PTR handleValue;
    QString status;
};



class FileUnlocker {
public:
    FileUnlocker();
    ~FileUnlocker();

    struct FileIdentifier {
        DWORD volumeSerial;
        ULONGLONG fileIndex;
        bool isValid;

        FileIdentifier() : volumeSerial(0), fileIndex(0), isValid(false) {}
    };

    // 获取占用文件的进程列表（包含完整句柄信息）
    QVector<ProcessInfo> getLockingProcesses(const QString& filePath);

    // 解锁文件（结束占用进程）
    bool unlockFile(const QString& filePath);

    // 关闭特定句柄
    bool closeSpecificHandle(DWORD processId, ULONG_PTR handle);

    // 结束特定进程
    bool terminateProcess(DWORD processId);

    // 解锁所有句柄
    bool unlockAllHandles(const QVector<ProcessInfo>& processes);

    // 检查文件是否被占用
    bool isFileLocked(const QString& filePath);

    // 获取错误信息
    QString getLastError() const { return m_lastError; }

private:
    // 使用重启管理器检测占用
    QVector<ProcessInfo> getLockingProcessesByRestartManager(const QString& filePath);

    // 使用内核对象遍历检测占用（获取详细句柄信息）
    QVector<ProcessInfo> getLockingProcessesByKernelObjects(const QString& filePath);

    // 为重启管理器找到的进程补充句柄信息
    QVector<ProcessInfo> supplementHandleInfo(const QVector<ProcessInfo>& restartManagerProcesses, const QString& filePath);

    // 关闭远程句柄
    bool closeRemoteHandle(DWORD processId, ULONG_PTR handle);

    // 获取进程完整路径
    QString getProcessPath(DWORD processId);

    // 从进程路径提取进程名
    QString getProcessNameFromPath(const QString& processPath);

    // 获取进程名
    QString getProcessName(DWORD processId);

    // 启用调试权限
    bool enableDebugPrivilege();

    // 获取文件的唯一标识
    FileIdentifier getFileIdentifier(const QString& filePath);

    QString m_lastError;
};

#endif // FILEUNLOCKER_H
