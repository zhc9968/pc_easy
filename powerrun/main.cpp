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
#include <shlwapi.h>

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
void ShowErrorDetails(const string& context, DWORD errorCode = GetLastError()); // 添加默认参数
void GodTrusted(const wchar_t* commandLine);

// 修复后的错误处理函数
void ShowErrorDetails(const string& context, DWORD errorCode) {
    // 使用宽字符版本获取错误信息
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
        // 正确转换宽字符到 QString
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

        // 命令输入框
        QLabel *label = new QLabel("请输入要运行的项目\n\n非可执行文件仅可使用管理员和普通用户的权限模式打开");
        layout->addWidget(label);

        commandEdit = new QLineEdit(this);
        layout->addWidget(commandEdit);

        // 按钮布局
        QHBoxLayout *buttonLayout = new QHBoxLayout();

        runButton = new QPushButton("运行", this);
        buttonLayout->addWidget(runButton);

        QPushButton *cancelButton = new QPushButton("取消", this);
        buttonLayout->addWidget(cancelButton);

        browseButton = new QPushButton("浏览...", this);
        buttonLayout->addWidget(browseButton);

        layout->addLayout(buttonLayout);

        // 连接信号
        connect(runButton, &QPushButton::clicked, this, &RunDialog::showRunOptions);
        connect(cancelButton, &QPushButton::clicked, this, &QWidget::close);
        connect(browseButton, &QPushButton::clicked, this, &RunDialog::browseFile);
    }

private slots:
    void showRunOptions() {
        QString command = commandEdit->text().trimmed();
        if (command.isEmpty()) return;

        // 检测是否为可执行文件
        bool isExecutable = false;
        wstring wcommand = command.toStdWString();
        if (PathFileExistsW(wcommand.c_str())) {
            DWORD binaryType;
            isExecutable = GetBinaryTypeW(wcommand.c_str(), &binaryType);
        }

        // 创建上下文菜单
        QMenu contextMenu(this);

        if (true) {
            // 可执行文件 - 显示所有选项
            contextMenu.addAction("受限用户")->setData(1);
            contextMenu.addAction("当前用户")->setData(2);
            contextMenu.addAction("管理员")->setData(3);
            contextMenu.addAction("SYSTEM")->setData(4);
            contextMenu.addAction("TrustedInstaller")->setData(5);
            contextMenu.addAction("最高令牌完整性")->setData(6);
        } else {
            // 非可执行文件 - 只显示普通用户和管理员选项
            contextMenu.addAction("普通用户运行")->setData(2);
            contextMenu.addAction("管理员运行")->setData(3);
        }

        QAction *selectedAction = contextMenu.exec(runButton->mapToGlobal(QPoint(0, runButton->height())));
        if (selectedAction) {
            int option = selectedAction->data().toInt();

            try {
                switch (option) {
                case 1: runRestrictedUser(command); break;
                case 2: runCurrentUser(command, isExecutable); break;
                case 3: runAsAdmin(command, isExecutable); break;
                case 4: runAsSystem(command); break;
                case 5: runAsTrustedInstaller(command); break;
                case 6: runWithHighestIntegrity(command); break;
                }
            } catch (const exception &e) {
                ShowErrorDetails(e.what()); // 修复：使用单参数调用
            }
        }
    }

    void browseFile() {
        QString file = QFileDialog::getOpenFileName(this, "选择程序", "", "所有文件 (*.*)");
        if (!file.isEmpty()) {
            commandEdit->setText(file);
        }
    }

private:
    void runRestrictedUser(const QString &command) {
        try {
            EnablePrivilege(SE_RELABEL_NAME);
            wstring cmd = command.toStdWString();

            // 获取当前进程令牌
            HANDLE hToken = NULL;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                throw runtime_error("OpenProcessToken失败");
            }

            // 创建受限令牌
            HANDLE hRestrictedToken = NULL;
            if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 0, nullptr, &hRestrictedToken)) {
                CloseHandle(hToken);
                throw runtime_error("CreateRestrictedToken失败");
            }

            // 复制令牌以便修改权限
            HANDLE hTokenToUse = hRestrictedToken;
            HANDLE hTempToken = NULL;
            if (DuplicateTokenEx(hRestrictedToken, TOKEN_ALL_ACCESS, NULL,
                                 SecurityImpersonation, TokenImpersonation, &hTempToken)) {
                hTokenToUse = hTempToken;
            }

            // 设置低完整性级别
            PSID lowSid = NULL;
            if (!ConvertStringSidToSid(L"S-1-16-4096", &lowSid)) {
                if (hTempToken) CloseHandle(hTempToken);
                CloseHandle(hRestrictedToken);
                CloseHandle(hToken);
                throw runtime_error("ConvertStringSidToSid失败");
            }

            TOKEN_MANDATORY_LABEL tml = {0};
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = lowSid;

            if (!SetTokenInformation(hTokenToUse, TokenIntegrityLevel, &tml, sizeof(tml))) {
                LocalFree(lowSid);
                if (hTempToken) CloseHandle(hTempToken);
                CloseHandle(hRestrictedToken);
                CloseHandle(hToken);
                throw runtime_error("SetTokenInformation失败");
            }
            LocalFree(lowSid);

            // 创建进程
            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            if (!CreateProcessAsUserW(
                    hTokenToUse,
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
                DWORD err = GetLastError();
                if (hTempToken) CloseHandle(hTempToken);
                CloseHandle(hRestrictedToken);
                CloseHandle(hToken);
                throw runtime_error("CreateProcessAsUser失败");
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            if (hTempToken) CloseHandle(hTempToken);
            CloseHandle(hRestrictedToken);
            CloseHandle(hToken);
        } catch (const exception &e) {
            ShowErrorDetails(e.what()); // 修复：使用单参数调用
        }
    }

    void runCurrentUser(const QString &command, bool isExecutable) {
        try {
            wstring cmd = command.toStdWString();

            if (isExecutable) {
                // 可执行文件 - 使用CreateProcess
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
                // 非可执行文件 - 使用ShellExecuteEx
                SHELLEXECUTEINFOW sei = { sizeof(sei) };
                sei.lpVerb = L"open";
                sei.lpFile = cmd.c_str();
                sei.nShow = SW_SHOWNORMAL;

                if (!ShellExecuteExW(&sei)) {
                    throw runtime_error("ShellExecuteEx失败");
                }
            }
        } catch (const exception &e) {
            ShowErrorDetails(e.what()); // 修复：使用单参数调用
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
                if (err == ERROR_CANCELLED) return; // 用户取消了UAC提示
                throw runtime_error("ShellExecuteEx失败");
            }
        } catch (const exception &e) {
            ShowErrorDetails(e.what()); // 修复：使用单参数调用
        }
    }

    void runAsSystem(const QString &command) {
        try {
            wstring cmd = command.toStdWString();

            // 确保我们有必要的特权
            EnablePrivilege(SE_DEBUG_NAME);
            EnablePrivilege(SE_RELABEL_NAME);
            EnablePrivilege(SE_IMPERSONATE_NAME);
            EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

            // 模拟SYSTEM用户
            ImpersonateSystem();

            // 获取模拟令牌
            HANDLE hToken = NULL;
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, FALSE, &hToken)) {
                throw runtime_error("OpenThreadToken失败");
            }

            // 复制令牌并设置完整性级别
            HANDLE hPrimaryToken = NULL;
            // 修复：修正DuplicateTokenEx参数
            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                                  SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
                CloseHandle(hToken);
                throw runtime_error("DuplicateTokenEx失败");
            }

            // 设置SYSTEM完整性级别
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

            // 创建新进程
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
            ShowErrorDetails(e.what()); // 修复：使用单参数调用
        }
        RevertToSelf();
    }

    void runAsTrustedInstaller(const QString &command) {
        try {
            trusted(command.toStdWString().c_str());
        } catch (const exception &e) {
            ShowErrorDetails(e.what()); // 修复：使用单参数调用
        }
    }

    void runWithHighestIntegrity(const QString &command) {
        try {
            EnablePrivilege(SE_RELABEL_NAME);
            GodTrusted(reinterpret_cast<const wchar_t *>(command.utf16()));
        } catch (const exception &e) {
            ShowErrorDetails(e.what()); // 修复：使用单参数调用
        }
    }

    QLineEdit *commandEdit;
    QPushButton *runButton;
    QPushButton *browseButton;
};

// 实现提供的辅助函数
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
        // 停止TrustedInstaller服务（如果正在运行）
        try {
            StopTrustedInstallerService();
        } catch (...) {
            // 忽略停止服务失败的错误
        }

        // 启动TrustedInstaller服务并获取进程ID
        auto pid = StartTrustedInstallerService();

        // 使用TrustedInstaller权限创建新进程
        CreateProcessAsTrustedInstaller(pid, L"\"" + commandLine + L"\"");
    }
    catch (const exception& e) {
        throw runtime_error(string("提权失败: ") + e.what());
    }

    return 0;
}

// ========== 常量定义 ==========
#define ML_SYSTEM_RID (0x00002000L) // 系统完整性级别
// ========== 辅助函数 ==========

// 获取所有特权列表
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

// 在令牌上启用所有特权
void EnableAllPrivileges(HANDLE hToken) {
    // 获取所有特权名称
    auto privileges = GetAllPrivileges();

    // 准备特权数组
    vector<LUID> luids;
    for (const auto& priv : privileges) {
        LUID luid;
        if (LookupPrivilegeValueW(nullptr, priv.c_str(), &luid)) {
            luids.push_back(luid);
        }
    }

    // 设置特权属性
    vector<TOKEN_PRIVILEGES> tpArray;
    for (const auto& luid : luids) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        tpArray.push_back(tp);
    }

    // 逐个启用特权
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
// 创建上帝模式令牌（SYSTEM + TrustedInstaller 结合体）
HANDLE CreateGodToken() {
    // 1. 获取 TrustedInstaller 令牌
    DWORD tiPid = 0;

    // 停止并重新启动 TrustedInstaller 服务
    try {
        StopTrustedInstallerService();
    } catch (...) {
        // 忽略停止失败
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

    // 2. 复制令牌以便修改
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

    // 3. 启用所有可能的特权
    EnableAllPrivileges(hGodToken);

    // // 4. 设置最高完整性级别
    // BOOL result = SetTokenInformation(
    //     hGodToken,
    //     TokenIntegrityLevel,
    //     (LPVOID)ML_SYSTEM_RID,
    //     sizeof(DWORD));

    // if (!result) {
    //     // 如果设置系统完整性失败，尝试高完整性
    //     DWORD integrityLevel = SECURITY_MANDATORY_HIGH_RID;
    //     if (!SetTokenInformation(
    //             hGodToken,
    //             TokenIntegrityLevel,
    //             &integrityLevel,
    //             sizeof(DWORD))) {
    //         CloseHandle(hGodToken);
    //         throw runtime_error("无法设置令牌完整性级别");
    //     }
    // }

    return hGodToken;
}

// GodTrusted 函数 - 创建具有所有特权的超级进程
void GodTrusted(const wchar_t* commandLine) {
    EnablePrivilege(SE_IMPERSONATE_NAME);
    // 1. 创建上帝令牌
    HANDLE hGodToken = CreateGodToken();
    if (hGodToken == NULL) {
        throw runtime_error("无法创建上帝令牌");
    }

    // 2. 确保当前进程有 SeAssignPrimaryTokenPrivilege 特权
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

    // 3. 使用 CreateProcessWithTokenW 创建进程
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    // 转换为可写字符串
    wstring cmdLine = commandLine;
    vector<wchar_t> writableCmdLine(cmdLine.begin(), cmdLine.end());
    writableCmdLine.push_back(L'\0');

    BOOL success = CreateProcessWithTokenW(
        hGodToken, // 主令牌
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

    // 清理资源
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hGodToken);
}

// 检查是否以管理员身份运行
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
    // 检查是否以管理员身份运行，如果不是则请求提升
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
