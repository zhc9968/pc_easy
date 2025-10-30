
#define _WIN32_WINNT 0x0600
#include <QtWidgets>
#include <QFileSystemModel>
#include <QHeaderView>
#include <QToolBar>
#include <QComboBox>
#include <QLineEdit>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <fileapi.h>
#include <winbase.h>
#include <winuser.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <strsafe.h>
#include <string>
#include <stdexcept>
#include <sstream>
#include <locale>
#include <codecvt>
#include <sddl.h>
#include <psapi.h>
#include <dbghelp.h>
#include <restartmanager.h>
#include "fileunlocker.h"
#include "fileunlockdialog.h"

using namespace std;

// 错误处理辅助函数 - 显示错误代码和消息
void ShowLastError(QWidget* parent, const wchar_t* action) {
    DWORD error = GetLastError();
    LPWSTR messageBuffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer, 0, NULL);

    QString errorMessage;
    if (size > 0) {
        errorMessage = QString("错误代码: %1\n错误描述: %2")
                           .arg(error)
                           .arg(QString::fromWCharArray(messageBuffer));
        LocalFree(messageBuffer);
    } else {
        errorMessage = QString("错误代码: %1\n无法获取错误描述").arg(error);
    }

    QMessageBox::critical(parent, "错误",
                          QString("%1\n\n%2").arg(QString::fromWCharArray(action)).arg(errorMessage));
}

// 在文件开头添加以下定义（在FileUnlocker类之前）
// 定义必要的Windows结构体
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
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

// 定义对象信息类
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

// 在 main.cpp 开头添加以下定义
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;


// 定义对象类型信息结构
typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName; // 现在使用定义的UNICODE_STRING
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;



// 定义Windows未公开API函数指针类型
typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* NtDuplicateObjectFunc)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* NtQueryObjectFunc)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* NtTerminateProcessFunc)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
    );


// 属性编辑器对话框类
class AttributeEditorDialog : public QDialog {
    Q_OBJECT
public:
    explicit AttributeEditorDialog(const QString &filePath, QWidget *parent = nullptr)
        : QDialog(parent), m_filePath(filePath) {
        setupUI();
        loadAttributes();
        loadZoneIdentifier();
    }

private:
    void setupUI() {
        setWindowTitle("编辑属性 - " + QFileInfo(m_filePath).fileName());
        resize(600, 500);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        // 创建滚动区域
        QScrollArea *scrollArea = new QScrollArea(this);
        scrollArea->setWidgetResizable(true);

        QWidget *scrollContent = new QWidget(scrollArea);
        QVBoxLayout *contentLayout = new QVBoxLayout(scrollContent);

        // 基本属性组
        QGroupBox *basicGroup = new QGroupBox("基本属性", scrollContent);
        QGridLayout *basicLayout = new QGridLayout(basicGroup);

        // 第一列
        readOnlyCheckBox = new QCheckBox("只读 (R)", basicGroup);
        hiddenCheckBox = new QCheckBox("隐藏 (H)", basicGroup);
        systemCheckBox = new QCheckBox("系统 (S)", basicGroup);
        directoryCheckBox = new QCheckBox("目录", basicGroup);
        directoryCheckBox->setEnabled(false); // 目录属性是只读的

        // 第二列
        archiveCheckBox = new QCheckBox("存档 (A)", basicGroup);
        normalCheckBox = new QCheckBox("正常", basicGroup);
        temporaryCheckBox = new QCheckBox("临时", basicGroup);
        compressedCheckBox = new QCheckBox("压缩", basicGroup);

        basicLayout->addWidget(readOnlyCheckBox, 0, 0);
        basicLayout->addWidget(hiddenCheckBox, 1, 0);
        basicLayout->addWidget(systemCheckBox, 2, 0);
        basicLayout->addWidget(directoryCheckBox, 3, 0);

        basicLayout->addWidget(archiveCheckBox, 0, 1);
        basicLayout->addWidget(normalCheckBox, 1, 1);
        basicLayout->addWidget(temporaryCheckBox, 2, 1);
        basicLayout->addWidget(compressedCheckBox, 3, 1);

        basicGroup->setLayout(basicLayout);
        contentLayout->addWidget(basicGroup);

        // 更多属性按钮
        moreButton = new QPushButton("显示更多属性 ▼", scrollContent);
        moreButton->setCheckable(true);
        moreButton->setChecked(false);
        contentLayout->addWidget(moreButton);

        // 高级属性组 (初始隐藏)
        advancedGroup = new QGroupBox("高级属性", scrollContent);
        QGridLayout *advancedLayout = new QGridLayout(advancedGroup);

        // 第一列
        deviceCheckBox = new QCheckBox("设备", advancedGroup);
        sparseFileCheckBox = new QCheckBox("稀疏文件", advancedGroup);
        reparsePointCheckBox = new QCheckBox("重解析点", advancedGroup);
        offlineCheckBox = new QCheckBox("脱机", advancedGroup);
        notContentIndexedCheckBox = new QCheckBox("无内容索引", advancedGroup);
        encryptedCheckBox = new QCheckBox("加密", advancedGroup);

        // 第二列
        integrityStreamCheckBox = new QCheckBox("完整性流", advancedGroup);
        virtualCheckBox = new QCheckBox("虚拟", advancedGroup);
        noScrubDataCheckBox = new QCheckBox("无清理数据", advancedGroup);
        eaCheckBox = new QCheckBox("扩展属性", advancedGroup);
        pinnedCheckBox = new QCheckBox("固定", advancedGroup);
        unpinnedCheckBox = new QCheckBox("取消固定", advancedGroup);

        advancedLayout->addWidget(deviceCheckBox, 0, 0);
        advancedLayout->addWidget(sparseFileCheckBox, 1, 0);
        advancedLayout->addWidget(reparsePointCheckBox, 2, 0);
        advancedLayout->addWidget(offlineCheckBox, 3, 0);
        advancedLayout->addWidget(notContentIndexedCheckBox, 4, 0);
        advancedLayout->addWidget(encryptedCheckBox, 5, 0);

        advancedLayout->addWidget(integrityStreamCheckBox, 0, 1);
        advancedLayout->addWidget(virtualCheckBox, 1, 1);
        advancedLayout->addWidget(noScrubDataCheckBox, 2, 1);
        advancedLayout->addWidget(eaCheckBox, 3, 1);
        advancedLayout->addWidget(pinnedCheckBox, 4, 1);
        advancedLayout->addWidget(unpinnedCheckBox, 5, 1);

        advancedGroup->setLayout(advancedLayout);
        advancedGroup->setVisible(false);
        contentLayout->addWidget(advancedGroup);

        // 连接更多属性按钮信号
        connect(moreButton, &QPushButton::toggled, this, [this](bool checked) {
            advancedGroup->setVisible(checked);
            moreButton->setText(checked ? "隐藏高级属性 ▲" : "显示更多属性 ▼");
        });

        // 区域标识符组
        QGroupBox *zoneGroup = new QGroupBox("区域标识符 (Zone.Identifier)", scrollContent);
        QVBoxLayout *zoneLayout = new QVBoxLayout(zoneGroup);

        // 区域标识符说明
        QLabel *zoneInfoLabel = new QLabel("此设置控制文件的安全警告级别。通常用于标记从互联网下载的文件。", zoneGroup);
        zoneInfoLabel->setWordWrap(true);
        zoneLayout->addWidget(zoneInfoLabel);

        // 区域标识符选项
        noZoneRadio = new QRadioButton("无区域标识符 (不显示安全警告)", zoneGroup);
        localZoneRadio = new QRadioButton("本地计算机 (ZoneId=0)", zoneGroup);
        trustedZoneRadio = new QRadioButton("可信站点 (ZoneId=2)", zoneGroup);
        internetZoneRadio = new QRadioButton("互联网 (ZoneId=3)", zoneGroup);
        restrictedZoneRadio = new QRadioButton("受限站点 (ZoneId=4)", zoneGroup);
        customZoneRadio = new QRadioButton("自定义", zoneGroup);

        zoneLayout->addWidget(noZoneRadio);
        zoneLayout->addWidget(localZoneRadio);
        zoneLayout->addWidget(trustedZoneRadio);
        zoneLayout->addWidget(internetZoneRadio);
        zoneLayout->addWidget(restrictedZoneRadio);
        zoneLayout->addWidget(customZoneRadio);

        // 自定义区域标识符编辑器
        customZoneEdit = new QPlainTextEdit(zoneGroup);
        customZoneEdit->setPlaceholderText("在此输入自定义区域标识符内容，例如:\n[ZoneTransfer]\nZoneId=3");
        customZoneEdit->setVisible(false);
        zoneLayout->addWidget(customZoneEdit);

        // 连接单选按钮信号
        connect(customZoneRadio, &QRadioButton::toggled, customZoneEdit, &QPlainTextEdit::setVisible);

        zoneGroup->setLayout(zoneLayout);
        contentLayout->addWidget(zoneGroup);

        // 自定义数据流组
        QGroupBox *customStreamGroup = new QGroupBox("自定义 NTFS 数据流", scrollContent);
        QFormLayout *streamLayout = new QFormLayout(customStreamGroup);

        streamNameEdit = new QLineEdit(customStreamGroup);
        streamNameEdit->setPlaceholderText("输入数据流名称 (不含冒号)");
        streamContentEdit = new QPlainTextEdit(customStreamGroup);
        streamContentEdit->setPlaceholderText("输入数据流内容");

        streamLayout->addRow("数据流名称:", streamNameEdit);
        streamLayout->addRow("数据流内容:", streamContentEdit);

        // 加载现有数据流按钮
        QPushButton *loadStreamButton = new QPushButton("加载数据流", customStreamGroup);
        connect(loadStreamButton, &QPushButton::clicked, this, [this]() {
            QString streamName = streamNameEdit->text().trimmed();
            if (streamName.isEmpty()) {
                QMessageBox::warning(this, "警告", "请输入数据流名称");
                return;
            }
            loadCustomStream(streamName);
        });

        streamLayout->addRow("", loadStreamButton);

        customStreamGroup->setLayout(streamLayout);
        contentLayout->addWidget(customStreamGroup);

        scrollContent->setLayout(contentLayout);
        scrollArea->setWidget(scrollContent);
        mainLayout->addWidget(scrollArea);

        // 按钮组
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *applyButton = new QPushButton("应用", this);
        QPushButton *okButton = new QPushButton("确定", this);
        QPushButton *cancelButton = new QPushButton("取消", this);

        buttonLayout->addWidget(applyButton);
        buttonLayout->addWidget(okButton);
        buttonLayout->addWidget(cancelButton);
        buttonLayout->addStretch();

        mainLayout->addLayout(buttonLayout);

        setLayout(mainLayout);

        // 连接信号
        connect(applyButton, &QPushButton::clicked, this, &AttributeEditorDialog::onApplyButtonClicked);
        connect(okButton, &QPushButton::clicked, this, &AttributeEditorDialog::onOkButtonClicked);
        connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    }

    void loadAttributes() {
        // 使用WINAPI获取文件属性
        DWORD attributes = GetFileAttributesW((LPCWSTR)m_filePath.utf16());

        if (attributes == INVALID_FILE_ATTRIBUTES) {
            ShowLastError(this, L"无法读取文件属性");
            return;
        }

        // 根据属性设置复选框状态
        readOnlyCheckBox->setChecked(attributes & FILE_ATTRIBUTE_READONLY);
        hiddenCheckBox->setChecked(attributes & FILE_ATTRIBUTE_HIDDEN);
        systemCheckBox->setChecked(attributes & FILE_ATTRIBUTE_SYSTEM);
        directoryCheckBox->setChecked(attributes & FILE_ATTRIBUTE_DIRECTORY);
        archiveCheckBox->setChecked(attributes & FILE_ATTRIBUTE_ARCHIVE);
        normalCheckBox->setChecked(attributes & FILE_ATTRIBUTE_NORMAL);
        temporaryCheckBox->setChecked(attributes & FILE_ATTRIBUTE_TEMPORARY);
        compressedCheckBox->setChecked(attributes & FILE_ATTRIBUTE_COMPRESSED);

        // 高级属性
        deviceCheckBox->setChecked(attributes & FILE_ATTRIBUTE_DEVICE);
        sparseFileCheckBox->setChecked(attributes & FILE_ATTRIBUTE_SPARSE_FILE);
        reparsePointCheckBox->setChecked(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
        offlineCheckBox->setChecked(attributes & FILE_ATTRIBUTE_OFFLINE);
        notContentIndexedCheckBox->setChecked(attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        encryptedCheckBox->setChecked(attributes & FILE_ATTRIBUTE_ENCRYPTED);
        integrityStreamCheckBox->setChecked(attributes & FILE_ATTRIBUTE_INTEGRITY_STREAM);
        virtualCheckBox->setChecked(attributes & FILE_ATTRIBUTE_VIRTUAL);
        noScrubDataCheckBox->setChecked(attributes & FILE_ATTRIBUTE_NO_SCRUB_DATA);
        eaCheckBox->setChecked(attributes & FILE_ATTRIBUTE_EA);
        pinnedCheckBox->setChecked(attributes & FILE_ATTRIBUTE_PINNED);
        unpinnedCheckBox->setChecked(attributes & FILE_ATTRIBUTE_UNPINNED);
    }

    void saveAttributes() {
        DWORD newAttributes = 0;

        // 基本属性
        if (readOnlyCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_READONLY;
        if (hiddenCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_HIDDEN;
        if (systemCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_SYSTEM;
        if (directoryCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_DIRECTORY;
        if (archiveCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_ARCHIVE;
        if (normalCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_NORMAL;
        if (temporaryCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_TEMPORARY;
        if (compressedCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_COMPRESSED;

        // 高级属性
        if (deviceCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_DEVICE;
        if (sparseFileCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_SPARSE_FILE;
        if (reparsePointCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
        if (offlineCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_OFFLINE;
        if (notContentIndexedCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        if (encryptedCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_ENCRYPTED;
        if (integrityStreamCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_INTEGRITY_STREAM;
        if (virtualCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_VIRTUAL;
        if (noScrubDataCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_NO_SCRUB_DATA;
        if (eaCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_EA;
        if (pinnedCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_PINNED;
        if (unpinnedCheckBox->isChecked()) newAttributes |= FILE_ATTRIBUTE_UNPINNED;

        // 应用新属性
        if (!SetFileAttributesW((LPCWSTR)m_filePath.utf16(), newAttributes)) {
            ShowLastError(this, L"无法设置文件属性");
        }
    }

    void loadZoneIdentifier() {
        // 构建Zone.Identifier数据流路径
        wstring streamPath = m_filePath.toStdWString() + L":Zone.Identifier";

        // 打开数据流
        HANDLE hStream = CreateFileW(
            streamPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
            );

        if (hStream == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND) {
                ShowLastError(this, L"无法打开Zone.Identifier数据流");
            }
            // 数据流不存在
            noZoneRadio->setChecked(true);
            return;
        }

        // 读取数据流内容
        const DWORD bufferSize = 1024;
        char buffer[bufferSize];
        DWORD bytesRead;
        string content;

        while (ReadFile(hStream, buffer, bufferSize - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            content += buffer;
        }

        CloseHandle(hStream);

        // 解析ZoneId值
        size_t zoneIdPos = content.find("ZoneId=");
        if (zoneIdPos != string::npos) {
            int zoneId = content[zoneIdPos + 7] - '0'; // 获取ZoneId值

            switch (zoneId) {
            case 0: localZoneRadio->setChecked(true); break;
            case 2: trustedZoneRadio->setChecked(true); break;
            case 3: internetZoneRadio->setChecked(true); break;
            case 4: restrictedZoneRadio->setChecked(true); break;
            default:
                customZoneRadio->setChecked(true);
                customZoneEdit->setPlainText(QString::fromStdString(content));
                break;
            }
        } else {
            customZoneRadio->setChecked(true);
            customZoneEdit->setPlainText(QString::fromStdString(content));
        }
    }

    void saveZoneIdentifier() {
        // 构建Zone.Identifier数据流路径
        wstring streamPath = m_filePath.toStdWString() + L":Zone.Identifier";

        // 根据选择设置内容
        string content;

        if (noZoneRadio->isChecked()) {
            // 删除数据流
            if (!DeleteFileW(streamPath.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
                ShowLastError(this, L"无法删除Zone.Identifier数据流");
            }
            return;
        } else if (localZoneRadio->isChecked()) {
            content = "[ZoneTransfer]\r\nZoneId=0";
        } else if (trustedZoneRadio->isChecked()) {
            content = "[ZoneTransfer]\r\nZoneId=2";
        } else if (internetZoneRadio->isChecked()) {
            content = "[ZoneTransfer]\r\nZoneId=3";
        } else if (restrictedZoneRadio->isChecked()) {
            content = "[ZoneTransfer]\r\nZoneId=4";
        } else if (customZoneRadio->isChecked()) {
            content = customZoneEdit->toPlainText().toStdString();
        }

        // 创建或打开数据流
        HANDLE hStream = CreateFileW(
            streamPath.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
            );

        if (hStream == INVALID_HANDLE_VALUE) {
            ShowLastError(this, L"无法创建或写入Zone.Identifier数据流");
            return;
        }

        // 写入内容
        DWORD bytesWritten;

        if (!WriteFile(hStream, content.c_str(), content.length(), &bytesWritten, NULL)) {
            ShowLastError(this, L"写入Zone.Identifier数据流时出错");
        }

        CloseHandle(hStream);
    }

    void loadCustomStream(const QString &streamName) {
        // 构建数据流路径
        wstring streamPath = m_filePath.toStdWString() + L":" + streamName.toStdWString();

        // 打开数据流
        HANDLE hStream = CreateFileW(
            streamPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
            );

        if (hStream == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) {
                QMessageBox::information(this, "信息", "指定的数据流不存在。");
            } else {
                ShowLastError(this, L"无法打开数据流");
            }
            return;
        }

        // 读取数据流内容
        const DWORD bufferSize = 4096;
        char buffer[bufferSize];
        DWORD bytesRead;
        string content;

        while (ReadFile(hStream, buffer, bufferSize - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            content += buffer;
        }

        CloseHandle(hStream);

        // 在文本编辑框中显示内容
        streamContentEdit->setPlainText(QString::fromStdString(content));
    }

    void saveCustomStream() {
        QString streamName = streamNameEdit->text().trimmed();
        if (streamName.isEmpty()) {
            return; // 没有要保存的自定义数据流
        }

        // 构建数据流路径
        wstring streamPath = m_filePath.toStdWString() + L":" + streamName.toStdWString();

        // 获取内容
        string content = streamContentEdit->toPlainText().toStdString();

        if (content.empty()) {
            // 内容为空，删除数据流
            if (!DeleteFileW(streamPath.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
                ShowLastError(this, L"无法删除数据流");
            }
            return;
        }

        // 创建或打开数据流
        HANDLE hStream = CreateFileW(
            streamPath.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
            );

        if (hStream == INVALID_HANDLE_VALUE) {
            ShowLastError(this, L"无法创建或写入数据流");
            return;
        }

        // 写入内容
        DWORD bytesWritten;

        if (!WriteFile(hStream, content.c_str(), content.length(), &bytesWritten, NULL)) {
            ShowLastError(this, L"写入数据流时出错");
        }

        CloseHandle(hStream);
    }

private slots:
    void onApplyButtonClicked() {
        saveZoneIdentifier();
        saveCustomStream();
        saveAttributes();
    }

    void onOkButtonClicked() {
        onApplyButtonClicked();
        accept();
    }

private:
    QString m_filePath;

    // 基本属性控件
    QCheckBox *readOnlyCheckBox;
    QCheckBox *hiddenCheckBox;
    QCheckBox *systemCheckBox;
    QCheckBox *directoryCheckBox;
    QCheckBox *archiveCheckBox;
    QCheckBox *normalCheckBox;
    QCheckBox *temporaryCheckBox;
    QCheckBox *compressedCheckBox;

    // 高级属性控件
    QPushButton *moreButton;
    QGroupBox *advancedGroup;
    QCheckBox *deviceCheckBox;
    QCheckBox *sparseFileCheckBox;
    QCheckBox *reparsePointCheckBox;
    QCheckBox *offlineCheckBox;
    QCheckBox *notContentIndexedCheckBox;
    QCheckBox *encryptedCheckBox;
    QCheckBox *integrityStreamCheckBox;
    QCheckBox *virtualCheckBox;
    QCheckBox *noScrubDataCheckBox;
    QCheckBox *eaCheckBox;
    QCheckBox *pinnedCheckBox;
    QCheckBox *unpinnedCheckBox;

    // Zone.Identifier 相关控件
    QRadioButton *noZoneRadio;
    QRadioButton *localZoneRadio;
    QRadioButton *trustedZoneRadio;
    QRadioButton *internetZoneRadio;
    QRadioButton *restrictedZoneRadio;
    QRadioButton *customZoneRadio;
    QPlainTextEdit *customZoneEdit;

    // 自定义数据流相关控件
    QLineEdit *streamNameEdit;
    QPlainTextEdit *streamContentEdit;
};

// 提权相关函数声明
void EnablePrivilege(wstring privilegeName);
DWORD GetProcessIdByName(wstring processName);
void ImpersonateSystem();
void StopTrustedInstallerService();
int StartTrustedInstallerService();
void CreateProcessAsTrustedInstaller(DWORD pid, wstring commandLine);
int trusted(const wchar_t* argv);
bool isPrivileged = false;

class Explorer : public QMainWindow {
    Q_OBJECT
public:
    Explorer(const QString &initialPath = "", const QString &selectFile = "", QWidget *parent = nullptr)
        : QMainWindow(parent), m_initialPath(initialPath), m_selectFile(selectFile) {
        setupUI();
        setupConnections();
        setWindowTitle("Qt Explorer");
        if (isPrivileged) {
            setWindowTitle("Qt Explorer [Trusted Installer] 高权限谨慎使用");
        }
        resize(1000, 600);
    }

private:
    void setupUI() {
        // 创建主部件
        QWidget *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);

        // 创建垂直布局
        QVBoxLayout *layout = new QVBoxLayout(centralWidget);

        // 创建工具栏和地址栏
        setupToolBar(layout);

        // 创建分割器
        QSplitter *splitter = new QSplitter(centralWidget);
        layout->addWidget(splitter);

        // 创建文件系统模型
        dirModel = new QFileSystemModel(this);
        dirModel->setRootPath("");
        dirModel->setFilter(QDir::Dirs | QDir::NoDotAndDotDot | QDir::Drives | QDir::System | QDir::Hidden);

        fileModel = new QFileSystemModel(this);
        fileModel->setRootPath("");
        fileModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::System | QDir::Hidden);
        fileModel->setReadOnly(false);

        // 左侧树形视图（只显示目录）
        treeView = new QTreeView(splitter);
        treeView->setModel(dirModel);
        treeView->setHeaderHidden(true);
        treeView->setAnimated(true);
        treeView->setIndentation(15);
        treeView->setSortingEnabled(true);
        treeView->sortByColumn(0, Qt::AscendingOrder);
        treeView->setSelectionMode(QAbstractItemView::SingleSelection);

        // 隐藏除名称外的所有列
        for (int i = 1; i < dirModel->columnCount(); ++i) {
            treeView->setColumnHidden(i, true);
        }

        // 右侧表格视图（显示详细文件信息）
        tableView = new QTableView(splitter);
        tableView->setModel(fileModel);
        tableView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setContextMenuPolicy(Qt::CustomContextMenu);
        tableView->setSortingEnabled(true);

        // 设置表头
        tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        tableView->horizontalHeader()->setStretchLastSection(true);
        tableView->verticalHeader()->setVisible(false);

        // 设置列宽
        tableView->setColumnWidth(0, 250); // 名称
        tableView->setColumnWidth(1, 80);  // 大小
        tableView->setColumnWidth(2, 120); // 类型
        tableView->setColumnWidth(3, 150); // 修改日期

        // 设置初始目录
        QString startPath = QDir::homePath();
        if (!m_initialPath.isEmpty() && QDir(m_initialPath).exists()) {
            startPath = m_initialPath;
        }

        QModelIndex homeIndex = dirModel->index(startPath);
        treeView->expand(homeIndex);
        treeView->setCurrentIndex(homeIndex);
        tableView->setRootIndex(fileModel->index(startPath));
        updateAddressBar(startPath);

        // 初始化历史记录
        history.append(startPath);
        historyIndex = 0;

        // 延迟选中文件（需要在UI初始化完成后）
        QTimer::singleShot(100, this, &Explorer::selectInitialFile);

        // 设置分割比例
        splitter->setSizes({200, 600});

        // 设置状态栏
        statusBar()->showMessage("就绪");

        // 启用拖放
        setAcceptDrops(true);
    }

    void selectInitialFile() {
        if (!m_selectFile.isEmpty()) {
            // 查找文件
            QModelIndex rootIndex = tableView->rootIndex();
            for (int row = 0; row < fileModel->rowCount(rootIndex); ++row) {
                QModelIndex index = fileModel->index(row, 0, rootIndex);
                if (fileModel->fileName(index) == m_selectFile) {
                    // 选中文件
                    tableView->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                    tableView->scrollTo(index);
                    break;
                }
            }
        }
    }

    void setupToolBar(QLayout *layout) {
        QToolBar *toolBar = new QToolBar(this);
        layout->addWidget(toolBar);

        // 后退按钮
        backAction = new QAction(QIcon::fromTheme("go-previous"), "后退", this);
        backAction->setShortcut(QKeySequence("Alt+Left"));
        toolBar->addAction(backAction);

        // 前进按钮
        forwardAction = new QAction(QIcon::fromTheme("go-next"), "前进", this);
        forwardAction->setShortcut(QKeySequence("Alt+Right"));
        toolBar->addAction(forwardAction);

        // 向上按钮
        upAction = new QAction(QIcon::fromTheme("go-up"), "向上", this);
        upAction->setShortcut(QKeySequence("Alt+Up"));
        toolBar->addAction(upAction);

        toolBar->addSeparator();

        // 地址栏
        addressCombo = new QComboBox(toolBar);
        addressCombo->setEditable(true);
        addressCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        addressCombo->setCompleter(new QCompleter(addressCombo));
        toolBar->addWidget(addressCombo);

        // 刷新按钮
        refreshAction = new QAction(QIcon::fromTheme("view-refresh"), "刷新", this);
        refreshAction->setShortcut(QKeySequence::Refresh);
        toolBar->addAction(refreshAction);

        toolBar->addSeparator();

        // 提权按钮
        if (!isPrivileged) {
            privilegeAction = new QAction(QIcon::fromTheme("security-high"), "提权", this);
            privilegeAction->setShortcut(QKeySequence("Ctrl+Shift+P"));
            toolBar->addAction(privilegeAction);
        }

        // 连接信号
        connect(backAction, &QAction::triggered, this, &Explorer::navigateBack);
        connect(forwardAction, &QAction::triggered, this, &Explorer::navigateForward);
        connect(upAction, &QAction::triggered, this, &Explorer::navigateUp);
        connect(refreshAction, &QAction::triggered, this, &Explorer::refreshView);
        connect(privilegeAction, &QAction::triggered, this, &Explorer::requestPrivilegeElevation);

        // 地址栏激活信号
        connect(addressCombo, QOverload<int>::of(&QComboBox::activated), this, [this](int index) {
            navigateToPath(addressCombo->itemText(index));
        });

        // 更新导航按钮状态
        updateNavigationButtons();
    }

    void setupConnections() {
        // 树视图选择变化时更新表格视图
        connect(treeView->selectionModel(), &QItemSelectionModel::currentChanged,
                this, [this](const QModelIndex &current) {
                    QString path = dirModel->filePath(current);
                    navigateToPath(path);
                });

        // 表格视图双击进入目录或打开文件
        connect(tableView, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
            if (fileModel->isDir(index)) {
                // 如果是目录，进入目录
                QString path = fileModel->filePath(index);
                navigateToPath(path);
            } else {
                // 如果是文件，使用默认程序打开
                QString path = fileModel->filePath(index);
                openFileWithDefaultProgram(path);
            }
        });

        // 表格视图右键菜单
        connect(tableView, &QTableView::customContextMenuRequested,
                this, &Explorer::showContextMenu);

        // 添加快捷键
        QShortcut *copyShortcut = new QShortcut(QKeySequence::Copy, tableView);
        connect(copyShortcut, &QShortcut::activated, this, &Explorer::copySelectedItems);

        QShortcut *pasteShortcut = new QShortcut(QKeySequence::Paste, tableView);
        connect(pasteShortcut, &QShortcut::activated, this, &Explorer::pasteItems);

        QShortcut *selectAllShortcut = new QShortcut(QKeySequence::SelectAll, tableView);
        connect(selectAllShortcut, &QShortcut::activated, this, &Explorer::selectAllItems);

        QShortcut *refreshShortcut = new QShortcut(QKeySequence::Refresh, tableView);
        connect(refreshShortcut, &QShortcut::activated, this, &Explorer::refreshView);
    }

    void updateAddressBar(const QString &path) {
        addressCombo->setCurrentText(path);
        // 添加到历史记录下拉列表
        if (addressCombo->findText(path) == -1) {
            addressCombo->addItem(path);
        }
    }

    void updateNavigationButtons() {
        backAction->setEnabled(historyIndex > 0);
        forwardAction->setEnabled(historyIndex < history.size() - 1);
    }

    void showContextMenu(const QPoint &pos) {
        QModelIndex index = tableView->indexAt(pos);
        QMenu menu;

        // 获取当前路径
        QString currentPath = fileModel->filePath(tableView->rootIndex());

        // 添加通用操作
        newFileAction = menu.addAction("新建文件");
        newFileAction->setShortcut(QKeySequence("Ctrl+N"));

        newFolderAction = menu.addAction("新建文件夹");
        newFolderAction->setShortcut(QKeySequence("Ctrl+Shift+N"));

        menu.addSeparator();

        copyAction = menu.addAction("复制");
        copyAction->setShortcut(QKeySequence::Copy);

        pasteAction = menu.addAction("粘贴");
        pasteAction->setShortcut(QKeySequence::Paste);

        menu.addSeparator();

        deleteAction = menu.addAction("删除");
        deleteAction->setShortcut(QKeySequence::Delete);

        renameAction = menu.addAction("重命名");
        renameAction->setShortcut(QKeySequence("F2"));

        menu.addSeparator();

        // 添加打开方式选项
        openWithAction = nullptr;
        if (index.isValid() && !fileModel->isDir(index)) {
            openWithAction = menu.addAction("打开方式");
            openWithAction->setShortcut(QKeySequence("Ctrl+O"));
        }

        menu.addSeparator();

        backMenuAction = menu.addAction("返回上级");
        backMenuAction->setShortcut(QKeySequence("Alt+Up"));

        refreshMenuAction = menu.addAction("刷新");
        refreshMenuAction->setShortcut(QKeySequence::Refresh);

        menu.addSeparator();

        // 添加属性编辑选项
        editAttributesAction = menu.addAction("编辑属性...");
        connect(editAttributesAction, &QAction::triggered, this, [this, index]() {
            QString path = fileModel->filePath(index);
            showAttributeEditorDialog(path);
        });

        // 添加解除占用选项
        QAction *unlockAction = menu.addAction("解除文件占用");
        connect(unlockAction, &QAction::triggered, this, [this, index]() {
            qDebug() << 1;
            QString path = fileModel->filePath(index);
            qDebug() << 2;
            unlockFile(path);
            qDebug() << 3;
        });

        menu.addSeparator();

        propertiesAction = menu.addAction("属性");
        propertiesAction->setShortcut(QKeySequence("Alt+Enter"));

        // 连接信号
        connect(newFileAction, &QAction::triggered, this, [this, currentPath]() { createNewFile(currentPath); });
        connect(newFolderAction, &QAction::triggered, this, [this, currentPath]() { createNewFolder(currentPath); });
        connect(copyAction, &QAction::triggered, this, &Explorer::copySelectedItems);
        connect(pasteAction, &QAction::triggered, this, &Explorer::pasteItems);
        connect(deleteAction, &QAction::triggered, this, [this]() { deleteSelectedItems(); });
        connect(renameAction, &QAction::triggered, this, [this, index]() { renameItem(index); });

        if (openWithAction) {
            connect(openWithAction, &QAction::triggered, this, [this, index]() {
                QString path = fileModel->filePath(index);
                showOpenWithDialog(path);
            });
        }

        connect(backMenuAction, &QAction::triggered, this, &Explorer::navigateUp);
        connect(refreshMenuAction, &QAction::triggered, this, &Explorer::refreshView);
        connect(propertiesAction, &QAction::triggered, this, [this]() { showNativeProperties(); });

        menu.exec(tableView->viewport()->mapToGlobal(pos));
    }

    void showAttributeEditorDialog(const QString &filePath) {
        AttributeEditorDialog dialog(filePath, this);
        dialog.exec();
    }

    // 在Explorer类中修改unlockFile方法
    void unlockFile(const QString &filePath) {
        FileUnlockDialog dialog(filePath, this);
        qDebug() << 4;

        // 连接打开路径信号
        connect(&dialog, &FileUnlockDialog::openInExplorer,
                this, &Explorer::navigateToPath);
        qDebug() << 5;

        dialog.exec();
        qDebug() << 6;

        // 解锁后刷新视图
        refreshView();
        qDebug() << 7;
    }

    void createNewFile(const QString &path) {
        bool ok;
        QString fileName = QInputDialog::getText(this, "新建文件", "文件名:",
                                                 QLineEdit::Normal, "新建文件.txt", &ok);
        if (ok && !fileName.isEmpty()) {
            QString fullPath = path + "\\" + fileName;
            HANDLE hFile = CreateFileW(
                (LPCWSTR)fullPath.utf16(),
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                NULL
                );

            if (hFile == INVALID_HANDLE_VALUE) {
                ShowLastError(this, L"无法创建文件");
                return;
            }

            CloseHandle(hFile);
            refreshView();
        }
    }

    void createNewFolder(const QString &path) {
        bool ok;
        QString folderName = QInputDialog::getText(this, "新建文件夹", "文件夹名:",
                                                   QLineEdit::Normal, "新建文件夹", &ok);
        if (ok && !folderName.isEmpty()) {
            QString fullPath = path + "\\" + folderName;
            if (!CreateDirectoryW((LPCWSTR)fullPath.utf16(), NULL)) {
                ShowLastError(this, L"无法创建文件夹");
            }
            refreshView();
        }
    }

    void copySelectedItems() {
        QModelIndexList selected = tableView->selectionModel()->selectedRows();
        if (selected.isEmpty()) return;

        QStringList paths;
        for (const QModelIndex &index : selected) {
            paths << fileModel->filePath(index);
        }

        // 复制文件路径到剪贴板
        QClipboard *clipboard = QApplication::clipboard();
        clipboard->setText(paths.join("\n"));

        statusBar()->showMessage(QString("已复制 %1 个项目").arg(selected.size()), 3000);
    }

    void pasteItems() {
        QClipboard *clipboard = QApplication::clipboard();
        QString clipboardText = clipboard->text();
        if (clipboardText.isEmpty()) return;

        QStringList paths = clipboardText.split("\n");
        if (paths.isEmpty()) return;

        QString currentPath = fileModel->filePath(tableView->rootIndex());

        // 只处理第一个路径（简化实现）
        QString sourcePath = paths.first();
        QFileInfo sourceInfo(sourcePath);
        QString destinationPath = currentPath + "\\" + sourceInfo.fileName();

        if (sourceInfo.isDir()) {
            // 复制目录
            if (!CopyDirectory(sourcePath, destinationPath)) {
                ShowLastError(this, L"无法复制目录");
            }
        } else {
            // 复制文件
            if (!CopyFileW((LPCWSTR)sourcePath.utf16(), (LPCWSTR)destinationPath.utf16(), FALSE)) {
                ShowLastError(this, L"无法复制文件");
            }
        }

        refreshView();
    }

    bool CopyDirectory(const QString &from, const QString &to) {
        QDir sourceDir(from);
        QDir targetDir(to);

        if (!targetDir.exists()) {
            if (!targetDir.mkpath(".")) {
                return false;
            }
        }

        QFileInfoList fileInfoList = sourceDir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
        foreach (const QFileInfo &fileInfo, fileInfoList) {
            QString sourceFilePath = fileInfo.filePath();
            QString targetFilePath = targetDir.filePath(fileInfo.fileName());

            if (fileInfo.isDir()) {
                if (!CopyDirectory(sourceFilePath, targetFilePath)) {
                    return false;
                }
            } else {
                if (!CopyFileW((LPCWSTR)sourceFilePath.utf16(), (LPCWSTR)targetFilePath.utf16(), FALSE)) {
                    ShowLastError(this, L"无法复制文件");
                    return false;
                }
            }
        }

        return true;
    }

    void selectAllItems() {
        tableView->selectAll();
    }

    void deleteSelectedItems() {
        QModelIndexList selected = tableView->selectionModel()->selectedRows();
        if (selected.isEmpty()) return;

        QStringList items;
        for (const QModelIndex &index : selected) {
            items << fileModel->fileName(index);
        }

        QString message = "确定要永久删除这 " + QString::number(selected.size()) + " 个项目吗?\n";
        message += "删除后无法恢复!\n\n";
        message += items.join("\n");

        QMessageBox::StandardButton reply;
        reply = QMessageBox::critical(this, "确认删除", message,
                                      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

        if (reply == QMessageBox::Yes) {
            for (const QModelIndex &index : selected) {
                QString path = fileModel->filePath(index);

                if (fileModel->isDir(index)) {
                    // 删除目录
                    if (!RemoveDirectoryW((LPCWSTR)path.utf16())) {
                        ShowLastError(this, L"无法删除文件夹");
                    }
                } else {
                    // 删除文件
                    if (!DeleteFileW((LPCWSTR)path.utf16())) {
                        ShowLastError(this, L"无法删除文件");
                    }
                }
            }
            refreshView();
        }
    }

    void renameItem(const QModelIndex &index) {
        if (!index.isValid()) return;

        QString oldPath = fileModel->filePath(index);
        QString oldName = fileModel->fileName(index);

        bool ok;
        QString newName = QInputDialog::getText(this, "重命名", "新名称:",
                                                QLineEdit::Normal, oldName, &ok);
        if (ok && !newName.isEmpty() && newName != oldName) {
            QString newPath = QFileInfo(oldPath).path() + "\\" + newName;

            if (!MoveFileW((LPCWSTR)oldPath.utf16(), (LPCWSTR)newPath.utf16())) {
                ShowLastError(this, L"无法重命名");
            }
            refreshView();
        }
    }

    void navigateToPath(const QString &path) {
        // 验证路径是否存在
        QDir dir(path);
        if (!dir.exists()) {
            QMessageBox::warning(this, "路径错误", "指定的路径不存在: " + path);
            return;
        }

        // 如果新路径与当前路径相同，则忽略
        if (!history.isEmpty() && history[historyIndex] == path) {
            return;
        }

        // 清除当前索引之后的历史记录
        if (historyIndex < history.size() - 1) {
            history = history.mid(0, historyIndex + 1);
        }

        // 添加新路径到历史记录
        history.append(path);
        historyIndex++;

        // 更新视图
        QModelIndex index = dirModel->index(path);
        if (index.isValid()) {
            treeView->setCurrentIndex(index);
            treeView->scrollTo(index);
            tableView->setRootIndex(fileModel->index(path));
            updateAddressBar(path);
            statusBar()->showMessage("当前目录: " + path);
        }

        // 更新导航按钮状态
        updateNavigationButtons();
    }

    void navigateBack() {
        if (historyIndex > 0) {
            historyIndex--;
            QString path = history[historyIndex];

            // 更新视图
            QModelIndex index = dirModel->index(path);
            if (index.isValid()) {
                treeView->setCurrentIndex(index);
                treeView->scrollTo(index);
                tableView->setRootIndex(fileModel->index(path));
                updateAddressBar(path);
                statusBar()->showMessage("当前目录: " + path);
            }

            // 更新导航按钮状态
            updateNavigationButtons();
        }
    }

    void navigateForward() {
        if (historyIndex < history.size() - 1) {
            historyIndex++;
            QString path = history[historyIndex];

            // 更新视图
            QModelIndex index = dirModel->index(path);
            if (index.isValid()) {
                treeView->setCurrentIndex(index);
                treeView->scrollTo(index);
                tableView->setRootIndex(fileModel->index(path));
                updateAddressBar(path);
                statusBar()->showMessage("当前目录: " + path);
            }

            // 更新导航按钮状态
            updateNavigationButtons();
        }
    }

    void navigateUp() {
        QModelIndex currentRoot = tableView->rootIndex();
        if (currentRoot.isValid()) {
            QModelIndex parent = currentRoot.parent();
            QString path = fileModel->filePath(parent);
            navigateToPath(path);
        }
    }

    void refreshView() {
        QString currentPath = fileModel->filePath(tableView->rootIndex());
        tableView->setRootIndex(fileModel->index(""));
        tableView->setRootIndex(fileModel->index(currentPath));
    }

    void showNativeProperties() {
        QModelIndexList selected = tableView->selectionModel()->selectedRows();
        if (selected.isEmpty()) return;

        // 只显示第一个选中项的属性
        QModelIndex index = selected.first();
        QString path = fileModel->filePath(index);

        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"properties";
        sei.lpFile = (LPCWSTR)path.replace("/", "\\").utf16();
        sei.nShow = SW_SHOW;
        sei.fMask = SEE_MASK_INVOKEIDLIST;

        if (!ShellExecuteEx(&sei)) {
            ShowLastError(this, L"无法显示属性对话框");
        }
    }

    void openFileWithDefaultProgram(QString &path) {
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"open";
        sei.lpFile = (LPCWSTR)path.replace("/", "\\").utf16();
        sei.nShow = SW_SHOW;
        sei.fMask = SEE_MASK_INVOKEIDLIST;

        if (!ShellExecuteEx(&sei)) {
            ShowLastError(this, L"无法打开文件");
        }
    }

    void showOpenWithDialog(QString &path) {
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"openas";
        sei.lpFile = (LPCWSTR)path.replace("/", "\\").utf16();
        sei.nShow = SW_SHOW;
        sei.fMask = SEE_MASK_INVOKEIDLIST;

        if (!ShellExecuteEx(&sei)) {
            ShowLastError(this, L"无法显示打开方式对话框");
        }
    }

    void requestPrivilegeElevation() {
        // 显示警告对话框
        QMessageBox::StandardButton reply;
        reply = QMessageBox::warning(this, "提权警告",
                                     "您确定要提权吗？\n\n"
                                     "提升权限后，您将获得对系统文件的完全访问权限。\n"
                                     "这可能导致意外修改或删除关键系统文件，造成系统不稳定甚至无法启动。\n\n"
                                     "请点击No或关闭弹窗，除非您十分清楚自己在干什么。",
                                     QMessageBox::Yes | QMessageBox::No);

        if (reply == QMessageBox::Yes) {
            // 获取当前可执行文件路径
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);

            // 尝试提权
            try {
                trusted(exePath);
                PostQuitMessage(0);
            } catch (const exception& e) {
                QMessageBox::critical(this, "提权失败", QString::fromLocal8Bit(e.what()));
            }
        }
    }

    // 拖放事件处理
    void dragEnterEvent(QDragEnterEvent *event) override {
        if (event->mimeData()->hasUrls()) {
            event->acceptProposedAction();
        }
    }

    void dropEvent(QDropEvent *event) override {
        const QMimeData *mimeData = event->mimeData();
        if (!mimeData->hasUrls()) return;

        QList<QUrl> urlList = mimeData->urls();
        if (urlList.isEmpty()) return;

        // 只处理第一个URL
        QString filePath = urlList.first().toLocalFile();
        QFileInfo fileInfo(filePath);

        if (fileInfo.isDir()) {
            // 如果是目录，导航到该目录
            navigateToPath(filePath);
        } else if (fileInfo.isFile()) {
            // 如果是文件，尝试打开
            openFileWithDefaultProgram(filePath);
        }
    }

    QFileSystemModel *dirModel;
    QFileSystemModel *fileModel;
    QTreeView *treeView;
    QTableView *tableView;
    QComboBox *addressCombo;
    QAction *backAction;
    QAction *forwardAction;
    QAction *upAction;
    QAction *refreshAction;
    QAction *privilegeAction;

    // 右键菜单动作
    QAction *newFileAction;
    QAction *newFolderAction;
    QAction *copyAction;
    QAction *pasteAction;
    QAction *deleteAction;
    QAction *renameAction;
    QAction *openWithAction;
    QAction *backMenuAction;
    QAction *refreshMenuAction;
    QAction *propertiesAction;
    QAction *editAttributesAction;
    QAction *unlockAction; // 解除占用动作
    QString m_initialPath;
    QString m_selectFile;

    QStringList history;
    int historyIndex = -1;
};

// ====================== 提权函数实现 ======================

void EnablePrivilege(wstring privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        throw runtime_error("OpenProcessToken失败: " + to_string(GetLastError()));

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid))
    {
        CloseHandle(hToken);
        throw runtime_error("LookupPrivilegeValue失败: " + to_string(GetLastError()));
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        CloseHandle(hToken);
        throw runtime_error("AdjustTokenPrivilege失败: " + to_string(GetLastError()));
    }

    CloseHandle(hToken);
}

DWORD GetProcessIdByName(wstring processName)
{
    HANDLE hSnapshot;
    if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
    {
        throw runtime_error("CreateToolhelp32Snapshot失败: " + to_string(GetLastError()));
    }

    DWORD pid = -1;
    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(PROCESSENTRY32W));
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe))
    {
        while (Process32NextW(hSnapshot, &pe))
        {
            if (wcscmp(pe.szExeFile, processName.c_str()) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        }
    }
    else
    {
        CloseHandle(hSnapshot);
        throw runtime_error("Process32First失败: " + to_string(GetLastError()));
    }

    if (pid == -1)
    {
        CloseHandle(hSnapshot);
        wstring_convert<codecvt_utf8<wchar_t>> converter;
        throw runtime_error("进程未找到: " + converter.to_bytes(processName));
    }

    CloseHandle(hSnapshot);
    return pid;
}

void ImpersonateSystem()
{
    auto systemPid = GetProcessIdByName(L"winlogon.exe");
    HANDLE hSystemProcess;
    if ((hSystemProcess = OpenProcess(
             PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
             FALSE,
             systemPid)) == nullptr)
    {
        throw runtime_error("OpenProcess失败 (winlogon.exe): " + to_string(GetLastError()));
    }

    HANDLE hSystemToken;
    if (!OpenProcessToken(
            hSystemProcess,
            MAXIMUM_ALLOWED,
            &hSystemToken))
    {
        CloseHandle(hSystemProcess);
        throw runtime_error("OpenProcessToken失败 (winlogon.exe): " + to_string(GetLastError()));
    }

    HANDLE hDupToken;
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
            &hDupToken))
    {
        CloseHandle(hSystemToken);
        throw runtime_error("DuplicateTokenEx失败 (winlogon.exe): " + to_string(GetLastError()));
    }

    if (!ImpersonateLoggedOnUser(hDupToken))
    {
        CloseHandle(hDupToken);
        CloseHandle(hSystemToken);
        throw runtime_error("ImpersonateLoggedOnUser失败: " + to_string(GetLastError()));
    }

    CloseHandle(hDupToken);
    CloseHandle(hSystemToken);
}

void StopTrustedInstallerService()
{
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL)
    {
        throw runtime_error("打开服务控制管理器失败: " + to_string(GetLastError()));
    }

    SC_HANDLE service = OpenService(scm, L"TrustedInstaller", SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service == NULL)
    {
        CloseServiceHandle(scm);
        throw runtime_error("打开TrustedInstaller服务失败: " + to_string(GetLastError()));
    }

    SERVICE_STATUS serviceStatus;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        throw runtime_error("停止TrustedInstaller服务失败: " + to_string(GetLastError()));
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

int StartTrustedInstallerService()
{
    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_IMPERSONATE_NAME);
    ImpersonateSystem();
    SC_HANDLE hSCManager;
    if ((hSCManager = OpenSCManagerW(
             nullptr,
             SERVICES_ACTIVE_DATABASE,
             SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS)) == nullptr)
    {
        throw runtime_error("OpenSCManager失败: " + to_string(GetLastError()));
    }

    SC_HANDLE hService;
    if ((hService = OpenServiceW(
             hSCManager,
             L"TrustedInstaller",
             SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)) == nullptr)
    {
        CloseServiceHandle(hSCManager);
        throw runtime_error("OpenService失败: " + to_string(GetLastError()));
    }

    // 检查服务是否被禁用
    DWORD dwBytesNeeded = 0;
    LPQUERY_SERVICE_CONFIGW pServiceConfig = nullptr;
    if (!QueryServiceConfigW(hService, nullptr, 0, &dwBytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        pServiceConfig = (LPQUERY_SERVICE_CONFIGW)malloc(dwBytesNeeded);
        if (pServiceConfig && QueryServiceConfigW(hService, pServiceConfig, dwBytesNeeded, &dwBytesNeeded))
        {
            if (pServiceConfig->dwStartType == SERVICE_DISABLED)
            {
                // 服务被禁用，尝试修改为手动启动
                if (!ChangeServiceConfigW(
                        hService,
                        SERVICE_NO_CHANGE,          // 服务类型不变
                        SERVICE_DEMAND_START,       // 改为手动启动
                        SERVICE_NO_CHANGE,          // 错误控制不变
                        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
                {
                    free(pServiceConfig);
                    CloseServiceHandle(hService);
                    CloseServiceHandle(hSCManager);
                    throw runtime_error("无法修改服务启动类型: " + to_string(GetLastError()));
                }
            }
        }
        free(pServiceConfig);
    }

    SERVICE_STATUS_PROCESS statusBuffer;
    DWORD bytesNeeded;
    while (QueryServiceStatusEx(
        hService,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&statusBuffer),
        sizeof(SERVICE_STATUS_PROCESS),
        &bytesNeeded))
    {
        if (statusBuffer.dwCurrentState == SERVICE_STOPPED)
        {
            if (!StartServiceW(hService, 0, nullptr))
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                throw runtime_error("StartService失败: " + to_string(GetLastError()));
            }
        }
        if (statusBuffer.dwCurrentState == SERVICE_START_PENDING ||
            statusBuffer.dwCurrentState == SERVICE_STOP_PENDING)
        {
            Sleep(statusBuffer.dwWaitHint);
            continue;
        }
        if (statusBuffer.dwCurrentState == SERVICE_RUNNING)
        {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return statusBuffer.dwProcessId;
        }
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    throw runtime_error("QueryServiceStatusEx失败: " + to_string(GetLastError()));
}

void CreateProcessAsTrustedInstaller(DWORD pid, wstring commandLine)
{
    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_IMPERSONATE_NAME);
    ImpersonateSystem();

    HANDLE hTIProcess;
    if ((hTIProcess = OpenProcess(
             PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
             FALSE,
             pid)) == nullptr)
    {
        throw runtime_error("OpenProcess失败 (TrustedInstaller.exe): " + to_string(GetLastError()));
    }

    HANDLE hTIToken;
    if (!OpenProcessToken(
            hTIProcess,
            MAXIMUM_ALLOWED,
            &hTIToken))
    {
        CloseHandle(hTIProcess);
        throw runtime_error("OpenProcessToken失败 (TrustedInstaller.exe): " + to_string(GetLastError()));
    }

    HANDLE hDupToken;
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
            &hDupToken))
    {
        CloseHandle(hTIToken);
        throw runtime_error("DuplicateTokenEx失败 (TrustedInstaller.exe): " + to_string(GetLastError()));
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
            &processInfo))
    {
        throw runtime_error("CreateProcessWithTokenW失败: " + to_string(GetLastError()));
    }
}

int trusted(const wchar_t* argv)
{
    wstring commandLine = argv;
    try {
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

bool IsRunningAsTrustedInstaller() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    DWORD size = 0;
    GetTokenInformation(hToken, TokenGroups, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return false;
    }

    PTOKEN_GROUPS pTokenGroups = (PTOKEN_GROUPS)malloc(size);
    if (!pTokenGroups) {
        CloseHandle(hToken);
        return false;
    }

    bool result = false;
    if (GetTokenInformation(hToken, TokenGroups, pTokenGroups, size, &size)) {
        PSID trustedInstallerSid = nullptr;
        if (ConvertStringSidToSidW(
                L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                &trustedInstallerSid
                )) {
            // 检查所有组中是否包含TrustedInstaller SID
            for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
                if (EqualSid(pTokenGroups->Groups[i].Sid, trustedInstallerSid) &&
                    (pTokenGroups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
                    result = true;
                    break;
                }
            }
            LocalFree(trustedInstallerSid);
        }
    }

    free(pTokenGroups);
    CloseHandle(hToken);
    return result;
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    isPrivileged = IsRunningAsTrustedInstaller();

    // 处理命令行参数
    QString initialPath;
    QString selectFile;

    if (argc > 1) {
        QString arg = QString::fromLocal8Bit(argv[1]);
        QFileInfo fileInfo(arg);

        if (fileInfo.exists()) {
            if (fileInfo.isDir()) {
                initialPath = fileInfo.absoluteFilePath();
            } else if (fileInfo.isFile()) {
                initialPath = fileInfo.absolutePath();
                selectFile = fileInfo.fileName();
            }
        }
        if (argc > 2) {
            FileUnlockDialog Dlg(fileInfo.absoluteFilePath());
            return Dlg.exec();
        }
    }


    Explorer explorer(initialPath, selectFile);
    explorer.show();
    return app.exec();
}

#include "main.moc"
