#include <QtWidgets>
#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <locale>
#include <codecvt>
#include <winternl.h>
#include <userenv.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <shlwapi.h>
#include <Lmcons.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "shlwapi.lib")

using namespace std;

// 辅助函数声明
void EnablePrivilege(wstring privilegeName);
DWORD GetProcessIdByName(wstring processName);
void ImpersonateSystem();
void StopTrustedInstallerService();
int StartTrustedInstallerService();
void CreateProcessAsTrustedInstaller(DWORD pid, wstring commandLine);
int trusted(const wchar_t* argv);
void ShowErrorDetails(const string& context, DWORD errorCode = GetLastError());
void GodTrusted(const wchar_t* commandLine);

// 新增函数声明
bool RunCommandLineMode(int argc, char* argv[]);
void ShowCommandLineHelp();
int ExecuteWithPrivilege(const QString& command, int privilegeLevel);
void ShowPrivilegeMenu(const QString& command);

// 修复后的错误处理函数
void ShowErrorDetails(const string& context, DWORD errorCode) {
    LPWSTR messageBuffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        NULL
        );

    QString message = QString::fromStdString(context) + "\n错误代码: " + QString::number(errorCode);

    if (size > 0 && messageBuffer != nullptr) {
        message += "\n错误信息: " + QString::fromWCharArray(messageBuffer, size);
    } else {
        message += "\n无法获取错误信息";
    }

    if (messageBuffer != nullptr) {
        LocalFree(messageBuffer);
    }

    QMessageBox::critical(nullptr, "错误", message);
}

class RunDialog : public QWidget {
    Q_OBJECT
public:
    RunDialog(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("运行");
        setFixedSize(400, 150);

        QVBoxLayout *layout = new QVBoxLayout(this);

        QLabel *label = new QLabel("请输入要运行的项目\n\n非可执行文件仅可使用管理员和普通用户的权限模式打开");
        layout->addWidget(label);

        commandEdit = new QLineEdit(this);
        layout->addWidget(commandEdit);

        QHBoxLayout *buttonLayout = new QHBoxLayout();

        runButton = new QPushButton("运行", this);
        buttonLayout->addWidget(runButton);

        QPushButton *cancelButton = new QPushButton("取消", this);
        buttonLayout->addWidget(cancelButton);

        browseButton = new QPushButton("浏览...", this);
        buttonLayout->addWidget(browseButton);

        layout->addLayout(buttonLayout);

        connect(runButton, &QPushButton::clicked, this, &RunDialog::showRunOptions);
        connect(cancelButton, &QPushButton::clicked, this, &QWidget::close);
        connect(browseButton, &QPushButton::clicked, this, &RunDialog::browseFile);
    }

    // 公开运行函数，供命令行模式使用
    void runWithOption(const QString& command, int option) {
        bool isExecutable = false;
        wstring wcommand = command.toStdWString();
        if (PathFileExistsW(wcommand.c_str())) {
            DWORD binaryType;
            isExecutable = GetBinaryTypeW(wcommand.c_str(), &binaryType);
        }

        try {
            switch (option) {
            case 1: runCurrentUser(command, isExecutable); break;
            case 2: runAsAdmin(command, isExecutable); break;
            case 3: runAsSystem(command); break;
            case 4: runAsTrustedInstaller(command); break;
            case 5: runWithHighestIntegrity(command); break;
            default: throw runtime_error("无效的运行选项");
            }
        } catch (const exception &e) {
            ShowErrorDetails(e.what());
        }
    }

    // 公开显示菜单函数
    void showRunOptionsForCommand(const QString& command) {
        bool isExecutable = false;
        wstring wcommand = command.toStdWString();
        if (PathFileExistsW(wcommand.c_str())) {
            DWORD binaryType;
            isExecutable = GetBinaryTypeW(wcommand.c_str(), &binaryType);
        }

        QMenu contextMenu;

        contextMenu.addAction("当前用户")->setData(1);
        contextMenu.addAction("管理员")->setData(2);
        contextMenu.addAction("SYSTEM")->setData(3);
        contextMenu.addAction("TrustedInstaller")->setData(4);
        contextMenu.addAction("最高令牌完整性")->setData(5);

        QAction *selectedAction = contextMenu.exec(QCursor::pos());
        if (selectedAction) {
            int option = selectedAction->data().toInt();
            runWithOption(command, option);
        }
    }

private slots:
    void showRunOptions() {
        QString command = commandEdit->text().trimmed();
        if (command.isEmpty()) return;
        showRunOptionsForCommand(command);
    }

    void browseFile() {
        QString file = QFileDialog::getOpenFileName(this, "选择程序", "", "所有文件 (*.*)");
        if (!file.isEmpty()) {
            commandEdit->setText(file);
        }
    }

private:
    // 获取用户组特权列表
    BOOL GetUserGroupPrivileges(PSID pUserGroupSID, PLUID* pPrivilegeLuid, PDWORD pDwCount) {
        LSA_OBJECT_ATTRIBUTES ObjectAttributes;
        ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

        LSA_HANDLE lsahPolicyHandle;
        NTSTATUS ntsResult = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);

        if (ntsResult != 0) {
            return FALSE;
        }

        PLSA_UNICODE_STRING UserRights = NULL;
        ULONG uRightCount;
        ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, pUserGroupSID, &UserRights, &uRightCount);

        if (ntsResult != 0) {
            LsaClose(lsahPolicyHandle);
            return FALSE;
        }

        *pDwCount = 0;
        *pPrivilegeLuid = (PLUID)LocalAlloc(LPTR, uRightCount * sizeof(LUID));
        if (*pPrivilegeLuid == NULL) {
            LsaFreeMemory(UserRights);
            LsaClose(lsahPolicyHandle);
            return FALSE;
        }

        for (ULONG uIdx = 0; uIdx < uRightCount; uIdx++) {
            int nLenOfMultiChars = WideCharToMultiByte(CP_ACP, 0, UserRights[uIdx].Buffer,
                                                       UserRights[uIdx].Length, NULL, 0, NULL, NULL);
            PSTR pMultiCharStr = (PSTR)HeapAlloc(GetProcessHeap(), 0, nLenOfMultiChars * sizeof(char));

            if (pMultiCharStr != NULL) {
                WideCharToMultiByte(CP_ACP, 0, UserRights[uIdx].Buffer, UserRights[uIdx].Length,
                                    pMultiCharStr, nLenOfMultiChars, NULL, NULL);

                LUID luid;
                if (LookupPrivilegeValueA(NULL, pMultiCharStr, &luid)) {
                    (*pPrivilegeLuid)[(*pDwCount)++] = luid;
                }
                HeapFree(GetProcessHeap(), 0, pMultiCharStr);
            }
        }

        LsaFreeMemory(UserRights);
        LsaClose(lsahPolicyHandle);
        return TRUE;
    }

    void runCurrentUser(const QString &command, bool isExecutable) {
        try {
            wstring cmd = command.toStdWString();

            if (isExecutable) {
                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi;
                if (!CreateProcessW(
                        nullptr,
                        const_cast<LPWSTR>(cmd.c_str()),
                        nullptr,
                        nullptr,
                        FALSE,
                        CREATE_NEW_CONSOLE,
                        nullptr,
                        nullptr,
                        &si,
                        &pi)) {
                    throw runtime_error("CreateProcess失败");
                }

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                SHELLEXECUTEINFOW sei = { sizeof(sei) };
                sei.lpVerb = L"open";
                sei.lpFile = cmd.c_str();
                sei.nShow = SW_SHOWNORMAL;

                if (!ShellExecuteExW(&sei)) {
                    throw runtime_error("ShellExecuteEx失败");
                }
            }
        } catch (const exception &e) {
            ShowErrorDetails(e.what());
        }
    }

    void runAsAdmin(const QString &command, bool isExecutable) {
        try {
            wstring cmd = command.toStdWString();

            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = cmd.c_str();
            sei.nShow = SW_SHOWNORMAL;

            if (!ShellExecuteExW(&sei)) {
                DWORD err = GetLastError();
                if (err == ERROR_CANCELLED) return;
                throw runtime_error("ShellExecuteEx失败");
            }
        } catch (const exception &e) {
            ShowErrorDetails(e.what());
        }
    }

    void runAsSystem(const QString &command) {
        try {
            wstring cmd = command.toStdWString();

            EnablePrivilege(SE_DEBUG_NAME);
            EnablePrivilege(SE_RELABEL_NAME);
            EnablePrivilege(SE_IMPERSONATE_NAME);
            EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

            ImpersonateSystem();

            HANDLE hToken = NULL;
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, FALSE, &hToken)) {
                throw runtime_error("OpenThreadToken失败");
            }

            HANDLE hPrimaryToken = NULL;
            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                                  SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
                CloseHandle(hToken);
                throw runtime_error("DuplicateTokenEx失败");
            }

            PSID systemSid = NULL;
            if (!ConvertStringSidToSid(L"S-1-16-16384", &systemSid)) {
                CloseHandle(hPrimaryToken);
                CloseHandle(hToken);
                throw runtime_error("ConvertStringSidToSid失败");
            }

            TOKEN_MANDATORY_LABEL tml = {0};
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = systemSid;

            if (!SetTokenInformation(hPrimaryToken, TokenIntegrityLevel, &tml, sizeof(tml))) {
                LocalFree(systemSid);
                CloseHandle(hPrimaryToken);
                CloseHandle(hToken);
                throw runtime_error("SetTokenInformation失败");
            }
            LocalFree(systemSid);

            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            if (!CreateProcessAsUserW(
                    hPrimaryToken,
                    nullptr,
                    const_cast<LPWSTR>(cmd.c_str()),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NEW_CONSOLE,
                    nullptr,
                    nullptr,
                    &si,
                    &pi)) {
                CloseHandle(hPrimaryToken);
                CloseHandle(hToken);
                throw runtime_error("CreateProcessAsUser失败");
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hPrimaryToken);
            CloseHandle(hToken);
        } catch (const exception &e) {
            RevertToSelf();
            ShowErrorDetails(e.what());
        }
        RevertToSelf();
    }

    void runAsTrustedInstaller(const QString &command) {
        try {
            trusted(command.toStdWString().c_str());
        } catch (const exception &e) {
            ShowErrorDetails(e.what());
        }
    }

    void runWithHighestIntegrity(const QString &command) {
        try {
            EnablePrivilege(SE_RELABEL_NAME);
            GodTrusted(reinterpret_cast<const wchar_t *>(command.utf16()));
        } catch (const exception &e) {
            ShowErrorDetails(e.what());
        }
    }

    QLineEdit *commandEdit;
    QPushButton *runButton;
    QPushButton *browseButton;
};

// 新增函数实现
bool RunCommandLineMode(int argc, char* argv[]) {
    if (argc < 2) {
        return false; // 没有参数，显示主窗口
    }

    QString command = QString::fromLocal8Bit(argv[1]);

    // 如果有第二个参数，直接使用指定权限运行
    if (argc >= 3) {
        bool ok;
        int privilegeLevel = QString(argv[2]).toInt(&ok);
        if (ok && privilegeLevel >= 1 && privilegeLevel <= 5) {
            ExecuteWithPrivilege(command, privilegeLevel);
            return true;
        } else {
            qCritical() << "错误: 无效的权限级别。必须是 1-5 之间的数字";
            ShowCommandLineHelp();
            return true;
        }
    }

    // 只有一个参数，显示权限选择菜单
    ShowPrivilegeMenu(command);
    return true;
}

void ShowCommandLineHelp() {
    qInfo() << "用法:";
    qInfo() << "  powerrun.exe <目标程序> [权限级别]";
    qInfo() << "";
    qInfo() << "权限级别:";
    qInfo() << "  1 - 当前用户";
    qInfo() << "  2 - 管理员";
    qInfo() << "  3 - SYSTEM";
    qInfo() << "  4 - TrustedInstaller";
    qInfo() << "  5 - 最高令牌完整性";
    qInfo() << "";
    qInfo() << "示例:";
    qInfo() << "  powerrun.exe cmd.exe 2        # 以管理员权限运行cmd";
    qInfo() << "  powerrun.exe notepad.exe      # 显示权限选择菜单";
    qInfo() << "  powerrun.exe                  # 显示GUI主窗口";
}

int ExecuteWithPrivilege(const QString& command, int privilegeLevel) {
    try {
        RunDialog dialog;
        dialog.runWithOption(command, privilegeLevel);
        return 0;
    } catch (const exception& e) {
        qCritical() << "执行失败:" << e.what();
        return 1;
    }
}

void ShowPrivilegeMenu(const QString& command) {
    QApplication app(__argc, __argv);

    // 创建隐藏的RunDialog实例来使用其菜单功能
    RunDialog* dialog = new RunDialog();
    dialog->showRunOptionsForCommand(command);

    // 菜单选择完成后退出应用
    QTimer::singleShot(100, &app, &QApplication::quit);
    app.exec();

    delete dialog;
}

// 原有的辅助函数实现保持不变
void EnablePrivilege(wstring privilegeName) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        throw runtime_error("OpenProcessToken失败");
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
        CloseHandle(hToken);
        throw runtime_error("LookupPrivilegeValue失败");
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        DWORD err = GetLastError();
        CloseHandle(hToken);
        wstring_convert<codecvt_utf8<wchar_t>> converter;
        string privName = converter.to_bytes(privilegeName);
        throw runtime_error("AdjustTokenPrivilege失败(" + privName + ")");
    }

    CloseHandle(hToken);
}

DWORD GetProcessIdByName(wstring processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        throw runtime_error("CreateToolhelp32Snapshot失败");
    }

    DWORD pid = -1;
    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(PROCESSENTRY32W));
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe)) {
        while (Process32NextW(hSnapshot, &pe)) {
            if (wcscmp(pe.szExeFile, processName.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        }
    } else {
        CloseHandle(hSnapshot);
        throw runtime_error("Process32First失败");
    }

    if (pid == -1) {
        CloseHandle(hSnapshot);
        wstring_convert<codecvt_utf8<wchar_t>> converter;
        throw runtime_error("进程未找到: " + converter.to_bytes(processName));
    }

    CloseHandle(hSnapshot);
    return pid;
}

void ImpersonateSystem() {
    auto systemPid = GetProcessIdByName(L"winlogon.exe");
    HANDLE hSystemProcess = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        FALSE,
        systemPid);
    if (hSystemProcess == nullptr) {
        throw runtime_error("OpenProcess失败 (winlogon.exe)");
    }

    HANDLE hSystemToken = NULL;
    if (!OpenProcessToken(
            hSystemProcess,
            MAXIMUM_ALLOWED,
            &hSystemToken)) {
        CloseHandle(hSystemProcess);
        throw runtime_error("OpenProcessToken失败 (winlogon.exe)");
    }

    HANDLE hDupToken = NULL;
    SECURITY_ATTRIBUTES tokenAttributes;
    tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    tokenAttributes.lpSecurityDescriptor = nullptr;
    tokenAttributes.bInheritHandle = FALSE;
    if (!DuplicateTokenEx(
            hSystemToken,
            MAXIMUM_ALLOWED,
            &tokenAttributes,
            SecurityImpersonation,
            TokenImpersonation,
            &hDupToken)) {
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        throw runtime_error("DuplicateTokenEx失败 (winlogon.exe)");
    }

    if (!ImpersonateLoggedOnUser(hDupToken)) {
        CloseHandle(hDupToken);
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        throw runtime_error("ImpersonateLoggedOnUser失败");
    }

    CloseHandle(hDupToken);
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);
}

void StopTrustedInstallerService() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        throw runtime_error("打开服务控制管理器失败");
    }

    SC_HANDLE service = OpenService(scm, L"TrustedInstaller", SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service == NULL) {
        CloseServiceHandle(scm);
        throw runtime_error("打开TrustedInstaller服务失败");
    }

    SERVICE_STATUS serviceStatus;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        throw runtime_error("停止TrustedInstaller服务失败");
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

int StartTrustedInstallerService() {
    try {
        EnablePrivilege(SE_DEBUG_NAME);
        EnablePrivilege(SE_IMPERSONATE_NAME);
        ImpersonateSystem();
    } catch (...) {
        // 忽略权限错误，可能已经拥有所需权限
    }

    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,
        SERVICES_ACTIVE_DATABASE,
        GENERIC_EXECUTE);
    if (hSCManager == nullptr) {
        throw runtime_error("OpenSCManager失败");
    }

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        L"TrustedInstaller",
        GENERIC_READ | GENERIC_EXECUTE);
    if (hService == nullptr) {
        CloseServiceHandle(hSCManager);
        throw runtime_error("OpenService失败");
    }

    SERVICE_STATUS_PROCESS statusBuffer;
    DWORD bytesNeeded;
    while (QueryServiceStatusEx(
        hService,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&statusBuffer),
        sizeof(SERVICE_STATUS_PROCESS),
        &bytesNeeded)) {
        if (statusBuffer.dwCurrentState == SERVICE_STOPPED) {
            if (!StartServiceW(hService, 0, nullptr)) {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                throw runtime_error("StartService失败");
            }
        }
        if (statusBuffer.dwCurrentState == SERVICE_START_PENDING ||
            statusBuffer.dwCurrentState == SERVICE_STOP_PENDING) {
            Sleep(statusBuffer.dwWaitHint);
            continue;
        }
        if (statusBuffer.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return statusBuffer.dwProcessId;
        }
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    throw runtime_error("QueryServiceStatusEx失败");
}

void CreateProcessAsTrustedInstaller(DWORD pid, wstring commandLine) {
    try {
        EnablePrivilege(SE_DEBUG_NAME);
        EnablePrivilege(SE_IMPERSONATE_NAME);
        ImpersonateSystem();
    } catch (...) {
        // 忽略权限错误，可能已经拥有所需权限
    }

    HANDLE hTIProcess = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        FALSE,
        pid);
    if (hTIProcess == nullptr) {
        throw runtime_error("OpenProcess失败 (TrustedInstaller.exe)");
    }

    HANDLE hTIToken = NULL;
    if (!OpenProcessToken(
            hTIProcess,
            MAXIMUM_ALLOWED,
            &hTIToken)) {
        CloseHandle(hTIProcess);
        throw runtime_error("OpenProcessToken失败 (TrustedInstaller.exe)");
    }

    HANDLE hDupToken = NULL;
    SECURITY_ATTRIBUTES tokenAttributes;
    tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    tokenAttributes.lpSecurityDescriptor = nullptr;
    tokenAttributes.bInheritHandle = FALSE;
    if (!DuplicateTokenEx(
            hTIToken,
            MAXIMUM_ALLOWED,
            &tokenAttributes,
            SecurityImpersonation,
            TokenImpersonation,
            &hDupToken)) {
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        throw runtime_error("DuplicateTokenEx失败 (TrustedInstaller.exe)");
    }

    STARTUPINFOW startupInfo;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
    if (!CreateProcessWithTokenW(
            hDupToken,
            LOGON_WITH_PROFILE,
            nullptr,
            const_cast<LPWSTR>(commandLine.c_str()),
            CREATE_UNICODE_ENVIRONMENT,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo)) {
        CloseHandle(hDupToken);
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        throw runtime_error("CreateProcessWithTokenW失败");
    }

    CloseHandle(hDupToken);
    CloseHandle(hTIToken);
    CloseHandle(hTIProcess);
}

int trusted(const wchar_t* argv) {
    wstring commandLine = argv;
    try {
        try {
            StopTrustedInstallerService();
        } catch (...) {
        }

        auto pid = StartTrustedInstallerService();
        CreateProcessAsTrustedInstaller(pid, L"\"" + commandLine + L"\"");
    }
    catch (const exception& e) {
        throw runtime_error(string("提权失败: ") + e.what());
    }

    return 0;
}

vector<wstring> GetAllPrivileges() {
    return {
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_AUDIT_NAME,
        SE_BACKUP_NAME,
        SE_CHANGE_NOTIFY_NAME,
        SE_CREATE_GLOBAL_NAME,
        SE_CREATE_PAGEFILE_NAME,
        SE_CREATE_PERMANENT_NAME,
        SE_CREATE_SYMBOLIC_LINK_NAME,
        SE_CREATE_TOKEN_NAME,
        SE_DEBUG_NAME,
        SE_ENABLE_DELEGATION_NAME,
        SE_IMPERSONATE_NAME,
        SE_INC_BASE_PRIORITY_NAME,
        SE_INCREASE_QUOTA_NAME,
        SE_LOAD_DRIVER_NAME,
        SE_LOCK_MEMORY_NAME,
        SE_MACHINE_ACCOUNT_NAME,
        SE_MANAGE_VOLUME_NAME,
        SE_PROF_SINGLE_PROCESS_NAME,
        SE_RELABEL_NAME,
        SE_REMOTE_SHUTDOWN_NAME,
        SE_RESTORE_NAME,
        SE_SECURITY_NAME,
        SE_SHUTDOWN_NAME,
        SE_SYNC_AGENT_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME,
        SE_SYSTEM_PROFILE_NAME,
        SE_SYSTEMTIME_NAME,
        SE_TAKE_OWNERSHIP_NAME,
        SE_TCB_NAME,
        SE_TIME_ZONE_NAME,
        SE_TRUSTED_CREDMAN_ACCESS_NAME,
        SE_UNDOCK_NAME,
        SE_UNSOLICITED_INPUT_NAME
    };
}

void EnableAllPrivileges(HANDLE hToken) {
    auto privileges = GetAllPrivileges();

    vector<LUID> luids;
    for (const auto& priv : privileges) {
        LUID luid;
        if (LookupPrivilegeValueW(nullptr, priv.c_str(), &luid)) {
            luids.push_back(luid);
        }
    }

    vector<TOKEN_PRIVILEGES> tpArray;
    for (const auto& luid : luids) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        tpArray.push_back(tp);
    }

    for (const auto& tp : tpArray) {
        if (!AdjustTokenPrivileges(
                hToken,
                FALSE,
                const_cast<PTOKEN_PRIVILEGES>(&tp),
                sizeof(TOKEN_PRIVILEGES),
                nullptr,
                nullptr)) {
            DWORD err = GetLastError();
            wchar_t msgBuffer[256];
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                err,
                0,
                msgBuffer,
                sizeof(msgBuffer)/sizeof(wchar_t),
                NULL);

            wstring_convert<codecvt_utf8<wchar_t>> converter;
            string errorMsg = converter.to_bytes(msgBuffer);
            throw runtime_error("启用特权失败: " + errorMsg);
        }
    }
}

HANDLE CreateGodToken() {
    DWORD tiPid = 0;

    try {
        StopTrustedInstallerService();
    } catch (...) {
    }

    tiPid = StartTrustedInstallerService();

    HANDLE hTIProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, tiPid);
    if (!hTIProcess) {
        throw runtime_error("无法打开 TrustedInstaller 进程");
    }

    HANDLE hTIToken = NULL;
    if (!OpenProcessToken(hTIProcess, TOKEN_ALL_ACCESS, &hTIToken)) {
        CloseHandle(hTIProcess);
        throw runtime_error("无法打开 TrustedInstaller 令牌");
    }

    HANDLE hGodToken = NULL;
    if (!DuplicateTokenEx(
            hTIToken,
            TOKEN_ALL_ACCESS,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &hGodToken)) {
        CloseHandle(hTIToken);
        CloseHandle(hTIProcess);
        throw runtime_error("无法复制 TrustedInstaller 令牌");
    }

    CloseHandle(hTIToken);
    CloseHandle(hTIProcess);

    EnablePrivilege(L"SeRelabelPrivilege");
    EnableAllPrivileges(hGodToken);

    return hGodToken;
}

void GodTrusted(const wchar_t* commandLine) {
    EnablePrivilege(SE_IMPERSONATE_NAME);
    HANDLE hGodToken = CreateGodToken();
    if (hGodToken == NULL) {
        throw runtime_error("无法创建上帝令牌");
    }

    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    wstring cmdLine = commandLine;
    vector<wchar_t> writableCmdLine(cmdLine.begin(), cmdLine.end());
    writableCmdLine.push_back(L'\0');

    BOOL success = CreateProcessWithTokenW(
        hGodToken,
        LOGON_WITH_PROFILE,
        NULL,
        writableCmdLine.data(),
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        NULL,
        NULL,
        &si,
        &pi);

    if (!success) {
        DWORD err = GetLastError();
        CloseHandle(hGodToken);

        wchar_t msgBuffer[512];
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            err,
            0,
            msgBuffer,
            sizeof(msgBuffer)/sizeof(wchar_t),
            NULL);

        wstring_convert<codecvt_utf8<wchar_t>> converter;
        string errorMsg = converter.to_bytes(msgBuffer);
        throw runtime_error("CreateProcessWithTokenW 失败: " + errorMsg);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hGodToken);
}

bool IsRunAsAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = NULL;
    BOOL b = FALSE;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &b);
        FreeSid(AdministratorsGroup);
    }
    return b == TRUE;
}

int main(int argc, char *argv[]) {
    // 首先检查命令行参数
    if (RunCommandLineMode(argc, argv)) {
        return 0;
    }

    // 如果没有命令行参数，检查管理员权限并显示主窗口
    if (!IsRunAsAdmin()) {
        wstring modulePath(MAX_PATH, L'\0');
        GetModuleFileNameW(NULL, &modulePath[0], MAX_PATH);

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = modulePath.c_str();
        sei.nShow = SW_SHOWNORMAL;

        if (ShellExecuteExW(&sei)) {
            return 0;
        }
    }

    QApplication app(argc, argv);
    RunDialog dialog;
    dialog.show();
    return app.exec();
}

#include "main.moc"
