#include <QApplication>
#include <QMainWindow>
#include <QTabWidget>
#include <QWidget>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QScrollArea>
#include <QStyle>
#include <QProcess>
#include <QTimer>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QEasingCurve>
#include <QMouseEvent>
#include <Windows.h>
#include <shellapi.h>
#include <QRadioButton>
#include <QButtonGroup>
#include <QGridLayout>
#include <QHBoxLayout>

// 错误处理辅助函数
void ShowLastError(QWidget* parent, const wchar_t* action) {
    DWORD error = GetLastError();
    if (error == 0) return;
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

// 注册表操作辅助函数
bool SetRegistryDWORD(HKEY hKey, const wchar_t* subKey, const wchar_t* valueName, DWORD data, QWidget* parent, const wchar_t* action) {
    HKEY hSubKey;
    LONG result = RegOpenKeyEx(hKey, subKey, 0, KEY_WRITE, &hSubKey);
    if (result != ERROR_SUCCESS) {
        ShowLastError(parent, action);
        return false;
    }

    result = RegSetValueEx(hSubKey, valueName, 0, REG_DWORD, (const BYTE*)&data, sizeof(DWORD));
    RegCloseKey(hSubKey);

    if (result != ERROR_SUCCESS) {
        ShowLastError(parent, action);
        return false;
    }
    return true;
}

bool GetRegistryDWORD(HKEY hKey, const wchar_t* subKey, const wchar_t* valueName, DWORD* data, QWidget* parent, const wchar_t* action) {
    HKEY hSubKey;
    LONG result = RegOpenKeyEx(hKey, subKey, 0, KEY_READ, &hSubKey);
    if (result != ERROR_SUCCESS) {
        ShowLastError(parent, action);
        return false;
    }

    DWORD type, size = sizeof(DWORD);
    result = RegQueryValueEx(hSubKey, valueName, NULL, &type, (LPBYTE)data, &size);
    RegCloseKey(hSubKey);

    if (result != ERROR_SUCCESS || type != REG_DWORD) {
        ShowLastError(parent, action);
        return false;
    }
    return true;
}

bool SetRegistrySZ(HKEY hKey, const wchar_t* subKey, const wchar_t* valueName, const wchar_t* data, QWidget* parent, const wchar_t* action) {
    HKEY hSubKey;
    LONG result = RegOpenKeyEx(hKey, subKey, 0, KEY_WRITE, &hSubKey);
    if (result != ERROR_SUCCESS) {
        ShowLastError(parent, action);
        return false;
    }

    result = RegSetValueEx(hSubKey, valueName, 0, REG_SZ, (const BYTE*)data, (wcslen(data) + 1) * sizeof(wchar_t));
    RegCloseKey(hSubKey);

    if (result != ERROR_SUCCESS) {
        ShowLastError(parent, action);
        return false;
    }
    return true;
}

bool GetRegistrySZ(HKEY hKey, const wchar_t* subKey, const wchar_t* valueName, wchar_t* buffer, DWORD bufferSize, QWidget* parent, const wchar_t* action) {
    HKEY hSubKey;
    LONG result = RegOpenKeyEx(hKey, subKey, 0, KEY_READ, &hSubKey);
    if (result != ERROR_SUCCESS) {
        ShowLastError(parent, action);
        return false;
    }

    DWORD type, size = bufferSize;
    result = RegQueryValueEx(hSubKey, valueName, NULL, &type, (LPBYTE)buffer, &size);
    RegCloseKey(hSubKey);

    if (result != ERROR_SUCCESS || type != REG_SZ) {
        ShowLastError(parent, action);
        return false;
    }
    return true;
}

bool DeleteRegistryValue(HKEY hKey, const wchar_t* subKey, const wchar_t* valueName, QWidget* parent, const wchar_t* action) {
    HKEY hSubKey;
    LONG result = RegOpenKeyEx(hKey, subKey, 0, KEY_WRITE, &hSubKey);
    if (result != ERROR_SUCCESS) {
        ShowLastError(parent, action);
        return false;
    }

    result = RegDeleteValue(hSubKey, valueName);
    RegCloseKey(hSubKey);

    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        ShowLastError(parent, action);
        return false;
    }
    return true;
}

// 美观的开关按钮类
class SwitchButton : public QWidget {
    Q_OBJECT
    Q_PROPERTY(int sliderPosition READ getSliderPosition WRITE setSliderPosition)

public:
    explicit SwitchButton(QWidget *parent = nullptr) : QWidget(parent), m_state(false) {
        setFixedSize(64, 32);
        m_animation = new QPropertyAnimation(this, "sliderPosition", this);
        m_animation->setDuration(150);
        m_animation->setEasingCurve(QEasingCurve::InOutQuad);

        updateSliderPosition();
    }

    bool isChecked() const { return m_state; }

    void setChecked(bool state) {
        if (m_state != state) {
            m_state = state;
            updateSliderPosition();
            update();
            emit stateChanged(m_state);
        }
    }

signals:
    void stateChanged(bool state);

protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);

        // 背景
        QPainterPath backgroundPath;
        backgroundPath.addRoundedRect(2, 2, width() - 4, height() - 4, 14, 14);

        QColor bgColor = m_state ? QColor("#4CAF50") : QColor("#E0E0E0");
        if (!isEnabled()) {
            bgColor = m_state ? QColor("#81C784") : QColor("#F5F5F5");
        }

        painter.fillPath(backgroundPath, bgColor);

        // 滑块
        QPainterPath sliderPath;
        int sliderSize = height() - 8;
        sliderPath.addEllipse(m_sliderPosition, 4, sliderSize, sliderSize);

        painter.fillPath(sliderPath, Qt::white);

        // 边框
        painter.setPen(QPen(QColor("#BDBDBD"), 1));
        painter.drawPath(backgroundPath);
    }

    void mousePressEvent(QMouseEvent *event) override {
        if (event->button() == Qt::LeftButton && isEnabled()) {
            setChecked(!m_state);
            event->accept();
        }
    }

    void enterEvent(QEnterEvent *event) override {
        setCursor(Qt::PointingHandCursor);
        QWidget::enterEvent(event);
    }

    void leaveEvent(QEvent *event) override {
        unsetCursor();
        QWidget::leaveEvent(event);
    }

private:
    int getSliderPosition() const { return m_sliderPosition; }

    void setSliderPosition(int position) {
        m_sliderPosition = position;
        update();
    }

    void updateSliderPosition() {
        int targetPos = m_state ? (width() - height() + 4) : 4;
        m_animation->setStartValue(m_sliderPosition);
        m_animation->setEndValue(targetPos);
        m_animation->start();
    }

    bool m_state;
    int m_sliderPosition = 4;
    QPropertyAnimation *m_animation;
};

class SystemOptimizer : public QMainWindow {
    Q_OBJECT

public:
    SystemOptimizer(QWidget *parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("系统优化器");
        setMinimumSize(800, 600);
        setStyleSheet("QMainWindow { background-color: #f5f5f5; }");

        // 检查管理员权限
        if (!IsRunAsAdmin()) {
            QMessageBox::warning(this, "警告", "请以管理员身份运行此程序以获得完整功能");
        }

        createUI();
        QTimer::singleShot(100, this, &SystemOptimizer::initSwitchStates);
    }

private:
    void createUI() {
        QTabWidget *tabWidget = new QTabWidget(this);
        tabWidget->setStyleSheet(R"(
            QTabWidget::pane { border: 1px solid #C2C7CB; background-color: white; }
            QTabWidget::tab-bar { alignment: center; }
            QTabBar::tab {
                background-color: #E0E0E0;
                color: #424242;
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid #C2C7CB;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                color: #2196F3;
                font-weight: bold;
            }
            QTabBar::tab:hover:!selected {
                background-color: #F5F5F5;
            }
        )");

        tabWidget->addTab(createSecurityPage(), "安全设置");
        tabWidget->addTab(createExplorerPage(), "资源管理器");
        tabWidget->addTab(createDesktopPage(), "桌面图标");
        tabWidget->addTab(createServicesPage(), "系统服务");

        setCentralWidget(tabWidget);
    }

    QWidget* createSecurityPage() {
        QWidget *page = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(page);
        layout->setSpacing(12);
        layout->setContentsMargins(16, 16, 16, 16);

        // 创建滚动区域
        QScrollArea *scrollArea = new QScrollArea;
        scrollArea->setWidgetResizable(true);
        scrollArea->setStyleSheet("background-color: transparent;");

        QWidget *scrollContent = new QWidget;
        QVBoxLayout *contentLayout = new QVBoxLayout(scrollContent);
        contentLayout->setSpacing(12);
        contentLayout->setContentsMargins(0, 0, 0, 0);

        // 安全设置组
        QGroupBox *securityGroup = createStyledGroupBox("安全设置");
        QVBoxLayout *securityLayout = new QVBoxLayout(securityGroup);

        addSwitchOption(securityLayout, "关闭Smartscreen应用筛选器",
                        "关闭SmartScreen筛选器功能", "SmartScreen");
        addSwitchOption(securityLayout, "关闭打开程序的'安全警告'",
                        "禁用未知程序运行警告", "SecurityWarning");
        addSwitchOption(securityLayout, "关闭防火墙",
                        "禁用Windows防火墙", "Firewall");
        addSwitchOption(securityLayout, "关闭远程协助",
                        "禁用远程协助功能", "RemoteAssistance");

        contentLayout->addWidget(securityGroup);

        // Windows更新设置
        QGroupBox *updateGroup = createStyledGroupBox("Windows更新设置");
        QVBoxLayout *updateLayout = new QVBoxLayout(updateGroup);

        addSwitchOption(updateLayout, "自动安装无需重启的更新",
                        "自动安装不需要重启的更新", "AutoInstallUpdates");

        QGroupBox *updatePolicyGroup = createStyledGroupBox("更新策略");
        QVBoxLayout *policyLayout = new QVBoxLayout(updatePolicyGroup);

        // 使用单选按钮组
        m_policyGroup = new QButtonGroup(this);

        QRadioButton *autoInstall = new QRadioButton("自动安装更新");
        QRadioButton *downloadNotify = new QRadioButton("检查并下载更新");
        QRadioButton *checkOnly = new QRadioButton("仅检查更新");
        QRadioButton *neverCheck = new QRadioButton("从不检查更新");

        m_policyGroup->addButton(autoInstall, 0);
        m_policyGroup->addButton(downloadNotify, 1);
        m_policyGroup->addButton(checkOnly, 2);
        m_policyGroup->addButton(neverCheck, 3);

        connect(m_policyGroup, QOverload<QAbstractButton *>::of(&QButtonGroup::buttonClicked),
                this, &SystemOptimizer::updatePolicyChanged);

        policyLayout->addWidget(autoInstall);
        policyLayout->addWidget(downloadNotify);
        policyLayout->addWidget(checkOnly);
        policyLayout->addWidget(neverCheck);

        updateLayout->addWidget(updatePolicyGroup);
        contentLayout->addWidget(updateGroup);

        contentLayout->addStretch();

        scrollContent->setLayout(contentLayout);
        scrollArea->setWidget(scrollContent);

        layout->addWidget(scrollArea);
        return page;
    }

    QWidget* createExplorerPage() {
        QWidget *page = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(page);
        layout->setSpacing(12);
        layout->setContentsMargins(16, 16, 16, 16);

        // 创建滚动区域
        QScrollArea *scrollArea = new QScrollArea;
        scrollArea->setWidgetResizable(true);
        scrollArea->setStyleSheet("background-color: transparent;");

        QWidget *scrollContent = new QWidget;
        QVBoxLayout *contentLayout = new QVBoxLayout(scrollContent);
        contentLayout->setSpacing(12);
        contentLayout->setContentsMargins(0, 0, 0, 0);

        QGroupBox *explorerGroup = createStyledGroupBox("资源管理器优化");
        QVBoxLayout *explorerLayout = new QVBoxLayout(explorerGroup);

        addSwitchOption(explorerLayout, "隐藏快捷方式小箭头",
                        "移除快捷方式图标上的小箭头", "ShortcutArrow");
        addSwitchOption(explorerLayout, "隐藏可执行文件小盾牌",
                        "移除可执行文件图标上的UAC盾牌", "ExecutableShield");
        addSwitchOption(explorerLayout, "收起资源管理器功能区",
                        "默认收起资源管理器功能区", "ExplorerRibbon");
        addSwitchOption(explorerLayout, "禁止自动播放",
                        "禁用自动运行功能", "AutoPlay");
        addSwitchOption(explorerLayout, "在单独的进程中打开文件夹",
                        "每个文件夹窗口使用独立进程", "SeparateProcess");
        addSwitchOption(explorerLayout, "快速访问不显示最近使用文件",
                        "隐藏最近使用的文件", "RecentFiles");
        addSwitchOption(explorerLayout, "快速访问不显示常用文件夹",
                        "隐藏常用文件夹", "FrequentFolders");
        addSwitchOption(explorerLayout, "禁用Win11新右键菜单",
                        "使用经典Win10右键菜单", "Win11ContextMenu");

        contentLayout->addWidget(explorerGroup);

        // 添加重启资源管理器按钮
        QPushButton *restartExplorerBtn = new QPushButton("重启资源管理器");
        restartExplorerBtn->setStyleSheet(R"(
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
        )");
        connect(restartExplorerBtn, &QPushButton::clicked, this, &SystemOptimizer::restartExplorer);
        contentLayout->addWidget(restartExplorerBtn, 0, Qt::AlignRight);
        contentLayout->addStretch();

        scrollContent->setLayout(contentLayout);
        scrollArea->setWidget(scrollContent);

        layout->addWidget(scrollArea);
        return page;
    }

    QWidget* createDesktopPage() {
        QWidget *page = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(page);
        layout->setSpacing(12);
        layout->setContentsMargins(16, 16, 16, 16);

        // 创建滚动区域
        QScrollArea *scrollArea = new QScrollArea;
        scrollArea->setWidgetResizable(true);
        scrollArea->setStyleSheet("background-color: transparent;");

        QWidget *scrollContent = new QWidget;
        QVBoxLayout *contentLayout = new QVBoxLayout(scrollContent);
        contentLayout->setSpacing(12);
        contentLayout->setContentsMargins(0, 0, 0, 0);

        QGroupBox *desktopGroup = createStyledGroupBox("桌面图标设置");
        QGridLayout *desktopLayout = new QGridLayout(desktopGroup);
        desktopLayout->setVerticalSpacing(8);

        int row = 0;
        addDesktopIconOption(desktopLayout, row++, "在桌面显示我的电脑", "显示'此电脑'图标", "ThisPC");
        addDesktopIconOption(desktopLayout, row++, "在桌面显示回收站", "显示'回收站'图标", "RecycleBin");
        addDesktopIconOption(desktopLayout, row++, "在桌面显示控制面板", "显示'控制面板'图标", "ControlPanel");
        addDesktopIconOption(desktopLayout, row++, "在桌面显示用户文件夹", "显示用户文件夹图标", "UserFiles");
        addDesktopIconOption(desktopLayout, row++, "在桌面显示网络", "显示'网络'图标", "Network");
        addDesktopIconOption(desktopLayout, row++, "在桌面显示库", "显示'库'图标", "Libraries");

        contentLayout->addWidget(desktopGroup);
        contentLayout->addStretch();

        scrollContent->setLayout(contentLayout);
        scrollArea->setWidget(scrollContent);

        layout->addWidget(scrollArea);
        return page;
    }

    QWidget* createServicesPage() {
        QWidget *page = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(page);
        layout->setSpacing(12);
        layout->setContentsMargins(16, 16, 16, 16);

        // 创建滚动区域
        QScrollArea *scrollArea = new QScrollArea;
        scrollArea->setWidgetResizable(true);
        scrollArea->setStyleSheet("background-color: transparent;");

        QWidget *scrollContent = new QWidget;
        QVBoxLayout *contentLayout = new QVBoxLayout(scrollContent);
        contentLayout->setSpacing(12);
        contentLayout->setContentsMargins(0, 0, 0, 0);

        QGroupBox *servicesGroup = createStyledGroupBox("系统服务设置");
        QVBoxLayout *servicesLayout = new QVBoxLayout(servicesGroup);

        addSwitchOption(servicesLayout, "关闭默认共享",
                        "禁用系统默认共享", "DefaultShares");
        addSwitchOption(servicesLayout, "关闭快速启动",
                        "禁用快速启动功能", "FastStartup");

        // 添加组策略选项
        QWidget *gpeditWidget = new QWidget;
        gpeditWidget->setStyleSheet("background-color: white; border-radius: 4px;");
        QHBoxLayout *gpeditLayout = new QHBoxLayout(gpeditWidget);
        gpeditLayout->setContentsMargins(12, 8, 12, 8);

        QVBoxLayout *gpeditTextLayout = new QVBoxLayout;
        gpeditTextLayout->setSpacing(2);

        QLabel *gpeditTitleLabel = new QLabel("启用组策略编辑器");
        gpeditTitleLabel->setStyleSheet("font-weight: bold; color: #424242; font-size: 11pt;");

        QLabel *gpeditDescLabel = new QLabel("在Windows家庭版上启用组策略编辑器(gpedit.msc)");
        gpeditDescLabel->setStyleSheet("color: #757575; font-size: 9pt;");
        gpeditDescLabel->setWordWrap(true);

        gpeditTextLayout->addWidget(gpeditTitleLabel);
        gpeditTextLayout->addWidget(gpeditDescLabel);

        SwitchButton *gpeditSwitch = new SwitchButton;
        m_switches["GroupPolicy"] = gpeditSwitch;

        connect(gpeditSwitch, &SwitchButton::stateChanged, this, [this](bool state){
            applySetting("GroupPolicy", state);
        });

        // 添加打开组策略按钮
        QPushButton *openGpeditBtn = new QPushButton("打开组策略");
        openGpeditBtn->setStyleSheet(R"(
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 9pt;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
            QPushButton:pressed {
                background-color: #1B5E20;
            }
            QPushButton:disabled {
                background-color: #A5D6A7;
            }
        )");
        connect(openGpeditBtn, &QPushButton::clicked, this, &SystemOptimizer::openGroupPolicy);

        gpeditLayout->addLayout(gpeditTextLayout, 1);
        gpeditLayout->addWidget(gpeditSwitch);
        gpeditLayout->addWidget(openGpeditBtn);
        gpeditLayout->setAlignment(gpeditSwitch, Qt::AlignVCenter);
        gpeditLayout->setAlignment(openGpeditBtn, Qt::AlignVCenter);

        servicesLayout->addWidget(gpeditWidget);

        contentLayout->addWidget(servicesGroup);
        contentLayout->addStretch();

        scrollContent->setLayout(contentLayout);
        scrollArea->setWidget(scrollContent);

        layout->addWidget(scrollArea);
        return page;
    }

    QGroupBox* createStyledGroupBox(const QString &title) {
        QGroupBox *groupBox = new QGroupBox(title);
        groupBox->setStyleSheet(R"(
            QGroupBox {
                font-weight: bold;
                color: #424242;
                border: 1px solid #DCDFE6;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px 0 8px;
                color: #2196F3;
            }
        )");
        return groupBox;
    }

    void addSwitchOption(QVBoxLayout *layout, const QString &title,
                         const QString &description, const QString &settingKey) {
        QWidget *optionWidget = new QWidget;
        optionWidget->setStyleSheet("background-color: white; border-radius: 4px;");
        QHBoxLayout *optionLayout = new QHBoxLayout(optionWidget);
        optionLayout->setContentsMargins(12, 8, 12, 8);

        QVBoxLayout *textLayout = new QVBoxLayout;
        textLayout->setSpacing(2);

        QLabel *titleLabel = new QLabel(title);
        titleLabel->setStyleSheet("font-weight: bold; color: #424242; font-size: 11pt;");

        QLabel *descLabel = new QLabel(description);
        descLabel->setStyleSheet("color: #757575; font-size: 9pt;");
        descLabel->setWordWrap(true);

        textLayout->addWidget(titleLabel);
        textLayout->addWidget(descLabel);

        SwitchButton *switchBtn = new SwitchButton;
        m_switches[settingKey] = switchBtn;

        connect(switchBtn, &SwitchButton::stateChanged, this, [this, settingKey](bool state){
            applySetting(settingKey, state);
        });

        optionLayout->addLayout(textLayout, 1);
        optionLayout->addWidget(switchBtn);
        optionLayout->setAlignment(switchBtn, Qt::AlignVCenter);

        layout->addWidget(optionWidget);
    }

    void addDesktopIconOption(QGridLayout *layout, int row, const QString &title,
                              const QString &description, const QString &settingKey) {
        QWidget *optionWidget = new QWidget;
        optionWidget->setStyleSheet("background-color: white; border-radius: 4px;");
        QHBoxLayout *optionLayout = new QHBoxLayout(optionWidget);
        optionLayout->setContentsMargins(12, 8, 12, 8);

        QVBoxLayout *textLayout = new QVBoxLayout;
        textLayout->setSpacing(2);

        QLabel *titleLabel = new QLabel(title);
        titleLabel->setStyleSheet("font-weight: bold; color: #424242; font-size: 11pt;");

        QLabel *descLabel = new QLabel(description);
        descLabel->setStyleSheet("color: #757575; font-size: 9pt;");

        textLayout->addWidget(titleLabel);
        textLayout->addWidget(descLabel);

        SwitchButton *switchBtn = new SwitchButton;
        m_switches[settingKey] = switchBtn;

        connect(switchBtn, &SwitchButton::stateChanged, this, [this, settingKey](bool state){
            applySetting(settingKey, state);
        });

        optionLayout->addLayout(textLayout, 1);
        optionLayout->addWidget(switchBtn);
        optionLayout->setAlignment(switchBtn, Qt::AlignVCenter);

        layout->addWidget(optionWidget, row, 0);
    }

    void applySetting(const QString &settingKey, bool state) {
        try {
            if (settingKey == "SmartScreen") {
                state ? disableSmartScreen() : enableSmartScreen();
            } else if (settingKey == "SecurityWarning") {
                state ? disableSecurityWarning() : enableSecurityWarning();
            } else if (settingKey == "Firewall") {
                state ? disableFirewall() : enableFirewall();
            } else if (settingKey == "RemoteAssistance") {
                state ? disableRemoteAssistance() : enableRemoteAssistance();
            } else if (settingKey == "ShortcutArrow") {
                state ? hideShortcutArrow() : showShortcutArrow();
            } else if (settingKey == "ExecutableShield") {
                state ? hideExecutableShield() : showExecutableShield();
            } else if (settingKey == "ExplorerRibbon") {
                state ? collapseExplorerRibbon() : expandExplorerRibbon();
            } else if (settingKey == "AutoPlay") {
                state ? disableAutoPlay() : enableAutoPlay();
            } else if (settingKey == "SeparateProcess") {
                state ? enableSeparateFolderProcess() : disableSeparateFolderProcess();
            } else if (settingKey == "RecentFiles") {
                state ? hideRecentFiles() : showRecentFiles();
            } else if (settingKey == "FrequentFolders") {
                state ? hideFrequentFolders() : showFrequentFolders();
            } else if (settingKey == "Win11ContextMenu") {
                state ? disableWin11ContextMenu() : enableWin11ContextMenu();
            } else if (settingKey == "ThisPC") {
                state ? showDesktopIcon("ThisPC") : hideDesktopIcon("ThisPC");
            } else if (settingKey == "RecycleBin") {
                state ? showDesktopIcon("RecycleBin") : hideDesktopIcon("RecycleBin");
            } else if (settingKey == "ControlPanel") {
                state ? showDesktopIcon("ControlPanel") : hideDesktopIcon("ControlPanel");
            } else if (settingKey == "UserFiles") {
                state ? showDesktopIcon("UserFiles") : hideDesktopIcon("UserFiles");
            } else if (settingKey == "Network") {
                state ? showDesktopIcon("Network") : hideDesktopIcon("Network");
            } else if (settingKey == "Libraries") {
                state ? showDesktopIcon("Libraries") : hideDesktopIcon("Libraries");
            } else if (settingKey == "AutoInstallUpdates") {
                state ? enableAutoInstallUpdates() : disableAutoInstallUpdates();
            } else if (settingKey == "DefaultShares") {
                state ? disableDefaultShares() : enableDefaultShares();
            } else if (settingKey == "FastStartup") {
                state ? disableFastStartup() : enableFastStartup();
            } else if (settingKey == "GroupPolicy") {
                enableGroupPolicy();
            }

            // 验证设置是否生效
            QTimer::singleShot(500, this, [this, settingKey]() {
                verifySetting(settingKey);
            });

        } catch (const std::exception& e) {
            QMessageBox::critical(this, "错误", QString("应用设置时发生错误: %1").arg(e.what()));
        }
    }

    void verifySetting(const QString &settingKey) {
        bool expected = m_switches[settingKey]->isChecked();
        bool actual = false;

        if (settingKey == "SmartScreen") {
            actual = isSmartScreenDisabled();
        } else if (settingKey == "SecurityWarning") {
            actual = isSecurityWarningDisabled();
        } else if (settingKey == "Firewall") {
            actual = isFirewallDisabled();
        } else if (settingKey == "RemoteAssistance") {
            actual = isRemoteAssistanceDisabled();
        } else if (settingKey == "ShortcutArrow") {
            actual = isShortcutArrowHidden();
        } else if (settingKey == "ExecutableShield") {
            actual = isExecutableShieldHidden();
        } else if (settingKey == "ExplorerRibbon") {
            actual = isExplorerRibbonCollapsed();
        } else if (settingKey == "AutoPlay") {
            actual = isAutoPlayDisabled();
        } else if (settingKey == "SeparateProcess") {
            actual = isSeparateFolderProcessEnabled();
        } else if (settingKey == "RecentFiles") {
            actual = isRecentFilesHidden();
        } else if (settingKey == "FrequentFolders") {
            actual = isFrequentFoldersHidden();
        } else if (settingKey == "Win11ContextMenu") {
            actual = isWin11ContextMenuDisabled();
        } else if (settingKey == "ThisPC") {
            actual = isDesktopIconVisible("ThisPC");
        } else if (settingKey == "RecycleBin") {
            actual = isDesktopIconVisible("RecycleBin");
        } else if (settingKey == "ControlPanel") {
            actual = isDesktopIconVisible("ControlPanel");
        } else if (settingKey == "UserFiles") {
            actual = isDesktopIconVisible("UserFiles");
        } else if (settingKey == "Network") {
            actual = isDesktopIconVisible("Network");
        } else if (settingKey == "Libraries") {
            actual = isDesktopIconVisible("Libraries");
        } else if (settingKey == "AutoInstallUpdates") {
            actual = isAutoInstallUpdatesEnabled();
        } else if (settingKey == "DefaultShares") {
            actual = isDefaultSharesDisabled();
        } else if (settingKey == "FastStartup") {
            actual = isFastStartupDisabled();
        } else if (settingKey == "GroupPolicy") {
            actual = isGroupPolicyEnabled();
        }

        if (expected != actual) {
            m_switches[settingKey]->setChecked(actual);
            QMessageBox::warning(this, "设置验证",
                                 "系统设置可能未被正确修改，请以管理员身份运行或检查系统权限");
        }
    }

    void updatePolicyChanged(QAbstractButton *button) {
        if (!m_policyGroup) return;
        int id = m_policyGroup->id(button);
        setUpdatePolicy(id);
    }

    void initSwitchStates() {
        // 初始化所有开关状态
        QMap<QString, SwitchButton*>::iterator i;
        for (i = m_switches.begin(); i != m_switches.end(); ++i) {
            bool state = false;
            QString key = i.key();

            if (key == "SmartScreen") state = isSmartScreenDisabled();
            else if (key == "SecurityWarning") state = isSecurityWarningDisabled();
            else if (key == "Firewall") state = isFirewallDisabled();
            else if (key == "RemoteAssistance") state = isRemoteAssistanceDisabled();
            else if (key == "ShortcutArrow") state = isShortcutArrowHidden();
            else if (key == "ExecutableShield") state = isExecutableShieldHidden();
            else if (key == "ExplorerRibbon") state = isExplorerRibbonCollapsed();
            else if (key == "AutoPlay") state = isAutoPlayDisabled();
            else if (key == "SeparateProcess") state = isSeparateFolderProcessEnabled();
            else if (key == "RecentFiles") state = isRecentFilesHidden();
            else if (key == "FrequentFolders") state = isFrequentFoldersHidden();
            else if (key == "Win11ContextMenu") state = isWin11ContextMenuDisabled();
            else if (key == "ThisPC") state = isDesktopIconVisible("ThisPC");
            else if (key == "RecycleBin") state = isDesktopIconVisible("RecycleBin");
            else if (key == "ControlPanel") state = isDesktopIconVisible("ControlPanel");
            else if (key == "UserFiles") state = isDesktopIconVisible("UserFiles");
            else if (key == "Network") state = isDesktopIconVisible("Network");
            else if (key == "Libraries") state = isDesktopIconVisible("Libraries");
            else if (key == "AutoInstallUpdates") state = isAutoInstallUpdatesEnabled();
            else if (key == "DefaultShares") state = isDefaultSharesDisabled();
            else if (key == "FastStartup") state = isFastStartupDisabled();
            else if (key == "GroupPolicy") state = isGroupPolicyEnabled();

            i.value()->blockSignals(true);
            i.value()->setChecked(state);
            i.value()->blockSignals(false);

            // 如果组策略已启用，禁用开关
            if (key == "GroupPolicy" && state) {
                i.value()->setEnabled(false);
            }
        }

        // 初始化更新策略单选按钮
        if (m_policyGroup) {
            int policy = getCurrentUpdatePolicy();
            QAbstractButton *button = m_policyGroup->button(policy);
            if (button) {
                button->setChecked(true);
            }
        }
    }

    // 重启资源管理器
    void restartExplorer() {
        QProcess::execute("taskkill", QStringList() << "/f" << "/im" << "explorer.exe");
        QProcess::startDetached("explorer.exe");
        QMessageBox::information(this, "操作完成", "资源管理器已成功重启");
    }

    // 打开组策略编辑器
    void openGroupPolicy() {
        if (isGroupPolicyEnabled()) {
            ShellExecuteW(NULL, L"runas", L"gpedit.msc", NULL, NULL, SW_SHOW);
        } else {
            QMessageBox::warning(this, "无法打开", "请先启用组策略编辑器");
        }
    }

    // 检查是否以管理员身份运行
    bool IsRunAsAdmin() {
        BOOL isAdmin = FALSE;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        PSID AdministratorsGroup;

        if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
            if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
                isAdmin = FALSE;
            }
            FreeSid(AdministratorsGroup);
        }
        return isAdmin == TRUE;
    }

    // 状态检测函数 - 使用Windows API
    bool isSmartScreenDisabled() {
        wchar_t value[256] = {0};
        if (GetRegistrySZ(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                          L"SmartScreenEnabled", value, sizeof(value), this, L"读取SmartScreen设置")) {
            return _wcsicmp(value, L"Off") == 0;
        }
        return false;
    }

    bool isSecurityWarningDisabled() {
        wchar_t value[256] = {0};
        if (GetRegistrySZ(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations",
                          L"LowRiskFileTypes", value, sizeof(value), this, L"读取安全警告设置")) {
            return wcslen(value) > 0;
        }
        return false;
    }

    bool isFirewallDisabled() {
        QProcess process;
        process.start("netsh", QStringList() << "advfirewall" << "show" << "allprofiles");
        if (process.waitForFinished(3000)) {
            QString output = process.readAllStandardOutput();
            return output.contains("关");
        }
        return false;
    }

    bool isRemoteAssistanceDisabled() {
        DWORD value = 1;
        if (GetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
                             L"fAllowToGetHelp", &value, this, L"读取远程协助设置")) {
            return value == 0;
        }
        return false;
    }

    bool isShortcutArrowHidden() {
        wchar_t value[256] = {0};
        if (GetRegistrySZ(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Icons",
                          L"29", value, sizeof(value), this, L"读取快捷方式箭头设置")) {
            return wcslen(value) > 0;
        }
        return false;
    }

    bool isExecutableShieldHidden() {
        DWORD value = 1;
        if (GetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                             L"EnableShield", &value, this, L"读取可执行文件盾牌设置")) {
            return value == 0;
        }
        return false;
    }

    bool isExplorerRibbonCollapsed() {
        DWORD value = 0;
        if (GetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Ribbon",
                             L"Minimized", &value, this, L"读取资源管理器功能区设置")) {
            return value == 1;
        }
        return false;
    }

    bool isAutoPlayDisabled() {
        DWORD value = 0;
        if (GetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                             L"NoDriveTypeAutoRun", &value, this, L"读取自动播放设置")) {
            return value == 255;
        }
        return false;
    }

    bool isSeparateFolderProcessEnabled() {
        DWORD value = 0;
        if (GetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                             L"SeparateProcess", &value, this, L"读取文件夹进程设置")) {
            return value == 1;
        }
        return false;
    }

    bool isRecentFilesHidden() {
        DWORD value = 1;
        if (GetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                             L"ShowRecent", &value, this, L"读取最近文件设置")) {
            return value == 0;
        }
        return false;
    }

    bool isFrequentFoldersHidden() {
        DWORD value = 1;
        if (GetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                             L"ShowFrequent", &value, this, L"读取常用文件夹设置")) {
            return value == 0;
        }
        return false;
    }

    bool isWin11ContextMenuDisabled() {
        HKEY hKey;
        LONG result = RegOpenKeyEx(HKEY_CURRENT_USER,
                                   L"Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32",
                                   0, KEY_READ, &hKey);

        if (result == ERROR_SUCCESS) {
            DWORD type, size = 0;
            // 先获取数据大小
            result = RegQueryValueEx(hKey, L"", NULL, &type, NULL, &size);

            if (result == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                // 如果值存在且为空字符串，表示禁用新菜单
                return size == 0 || (size == 2 && type == REG_SZ); // 空字符串大小为2（包含终止符）
            }
            RegCloseKey(hKey);
        }
        return false;
    }
    bool isDesktopIconVisible(const QString &iconName) {
        const wchar_t* guid = L"";
        if (iconName == "ThisPC") guid = L"{20D04FE0-3AEA-1069-A2D8-08002B30309D}";
        else if (iconName == "RecycleBin") guid = L"{645FF040-5081-101B-9F08-00AA002F954E}";
        else if (iconName == "ControlPanel") guid = L"{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}";
        else if (iconName == "UserFiles") guid = L"{59031a47-3f72-44a7-89c5-5595fe6b30ee}";
        else if (iconName == "Network") guid = L"{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}";
        else if (iconName == "Libraries") guid = L"{031E4825-7B94-4dc3-B131-E946B44C8DD5}";

        DWORD value = 1;
        if (GetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel",
                             guid, &value, this, L"读取桌面图标设置")) {
            return value == 0;
        }
        return false;
    }

    bool isAutoInstallUpdatesEnabled() {
        DWORD value = 0;
        if (GetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
                             L"AutoInstallMinorUpdates", &value, this, L"读取自动更新设置")) {
            return value == 1;
        }
        return false;
    }

    bool isDefaultSharesDisabled() {
        DWORD value = 1;
        if (GetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                             L"AutoShareWks", &value, this, L"读取默认共享设置")) {
            return value == 0;
        }
        return false;
    }

    bool isFastStartupDisabled() {
        DWORD value = 1;
        if (GetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
                             L"HiberbootEnabled", &value, this, L"读取快速启动设置")) {
            return value == 0;
        }
        return false;
    }

    // 检查组策略是否已启用
    bool isGroupPolicyEnabled() {
        // 检查gpedit.msc文件是否存在
        wchar_t systemPath[MAX_PATH];
        GetSystemDirectoryW(systemPath, MAX_PATH);
        std::wstring gpeditPath = std::wstring(systemPath) + L"\\gpedit.msc";

        DWORD attrib = GetFileAttributesW(gpeditPath.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    int getCurrentUpdatePolicy() {
        DWORD noAutoUpdate = 0;
        DWORD auOptions = 0;

        // 尝试读取策略设置
        GetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                         L"NoAutoUpdate", &noAutoUpdate, this, L"读取更新策略");
        GetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                         L"AUOptions", &auOptions, this, L"读取更新策略");

        if (noAutoUpdate == 1) {
            return 3; // 从不检查更新
        } else if (auOptions == 4) {
            return 0; // 自动安装更新
        } else if (auOptions == 3) {
            return 1; // 检查并下载更新
        } else if (auOptions == 2) {
            return 2; // 仅检查更新
        }

        // 默认返回自动安装更新
        return 0;
    }

    // 以下是各个优化功能的实现函数 - 使用Windows API
    void disableSmartScreen() {
        SetRegistrySZ(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                      L"SmartScreenEnabled", L"Off", this, L"禁用SmartScreen");
    }

    void enableSmartScreen() {
        SetRegistrySZ(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                      L"SmartScreenEnabled", L"On", this, L"启用SmartScreen");
    }

    void disableSecurityWarning() {
        SetRegistrySZ(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations",
                      L"LowRiskFileTypes", L".exe;.bat;.cmd;.vbs", this, L"禁用安全警告");
    }

    void enableSecurityWarning() {
        DeleteRegistryValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations",
                            L"LowRiskFileTypes", this, L"启用安全警告");
    }

    void disableFirewall() {
        QProcess::startDetached("netsh", QStringList() << "advfirewall" << "set" << "allprofiles" << "state" << "off");
    }

    void enableFirewall() {
        QProcess::startDetached("netsh", QStringList() << "advfirewall" << "set" << "allprofiles" << "state" << "on");
    }

    void disableRemoteAssistance() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
                         L"fAllowToGetHelp", 0, this, L"禁用远程协助");
    }

    void enableRemoteAssistance() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
                         L"fAllowToGetHelp", 1, this, L"启用远程协助");
    }

    void hideShortcutArrow() {
        SetRegistrySZ(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Icons",
                      L"29", L"%SystemRoot%\\System32\\shell32.dll,-50", this, L"隐藏快捷方式箭头");
    }

    void showShortcutArrow() {
        DeleteRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Icons",
                            L"29", this, L"显示快捷方式箭头");
    }

    void hideExecutableShield() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                         L"EnableShield", 0, this, L"隐藏可执行文件盾牌");
    }

    void showExecutableShield() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                         L"EnableShield", 1, this, L"显示可执行文件盾牌");
    }

    void collapseExplorerRibbon() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Ribbon",
                         L"Minimized", 1, this, L"收起资源管理器功能区");
    }

    void expandExplorerRibbon() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Ribbon",
                         L"Minimized", 0, this, L"展开资源管理器功能区");
    }

    void disableAutoPlay() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                         L"NoDriveTypeAutoRun", 255, this, L"禁用自动播放");
    }

    void enableAutoPlay() {
        DeleteRegistryValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                            L"NoDriveTypeAutoRun", this, L"启用自动播放");
    }

    void enableSeparateFolderProcess() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                         L"SeparateProcess", 1, this, L"启用独立文件夹进程");
    }

    void disableSeparateFolderProcess() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                         L"SeparateProcess", 0, this, L"禁用独立文件夹进程");
    }

    void hideRecentFiles() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                         L"ShowRecent", 0, this, L"隐藏最近文件");
    }

    void showRecentFiles() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                         L"ShowRecent", 1, this, L"显示最近文件");
    }

    void hideFrequentFolders() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                         L"ShowFrequent", 0, this, L"隐藏常用文件夹");
    }

    void showFrequentFolders() {
        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                         L"ShowFrequent", 1, this, L"显示常用文件夹");
    }

    void disableWin11ContextMenu() {
        HKEY hKey;
        LONG result = RegCreateKeyEx(HKEY_CURRENT_USER,
                                     L"Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32",
                                     0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

        if (result == ERROR_SUCCESS) {
            // 设置空字符串值
            result = RegSetValueEx(hKey, L"", 0, REG_SZ, (const BYTE*)L"", 2);
            RegCloseKey(hKey);

            if (result != ERROR_SUCCESS) {
                ShowLastError(this, L"禁用Win11右键菜单");
            }
        } else {
            ShowLastError(this, L"创建注册表键");
        }
    }

    void enableWin11ContextMenu() {
        // 删除整个CLSID键来恢复默认设置
        LONG result = RegDeleteTree(HKEY_CURRENT_USER,
                                    L"Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}");

        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
            ShowLastError(this, L"启用Win11右键菜单");
        }
    }

    void showDesktopIcon(const QString &iconName) {
        const wchar_t* guid = L"";
        if (iconName == "ThisPC") guid = L"{20D04FE0-3AEA-1069-A2D8-08002B30309D}";
        else if (iconName == "RecycleBin") guid = L"{645FF040-5081-101B-9F08-00AA002F954E}";
        else if (iconName == "ControlPanel") guid = L"{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}";
        else if (iconName == "UserFiles") guid = L"{59031a47-3f72-44a7-89c5-5595fe6b30ee}";
        else if (iconName == "Network") guid = L"{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}";
        else if (iconName == "Libraries") guid = L"{031E4825-7B94-4dc3-B131-E946B44C8DD5}";

        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel",
                         guid, 0, this, L"显示桌面图标");
    }

    void hideDesktopIcon(const QString &iconName) {
        const wchar_t* guid = L"";
        if (iconName == "ThisPC") guid = L"{20D04FE0-3AEA-1069-A2D8-08002B30309D}";
        else if (iconName == "RecycleBin") guid = L"{645FF040-5081-101B-9F08-00AA002F954E}";
        else if (iconName == "ControlPanel") guid = L"{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}";
        else if (iconName == "UserFiles") guid = L"{59031a47-3f72-44a7-89c5-5595fe6b30ee}";
        else if (iconName == "Network") guid = L"{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}";
        else if (iconName == "Libraries") guid = L"{031E4825-7B94-4dc3-B131-E946B44C8DD5}";

        SetRegistryDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel",
                         guid, 1, this, L"隐藏桌面图标");
    }

    void enableAutoInstallUpdates() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
                         L"AutoInstallMinorUpdates", 1, this, L"启用自动安装更新");
    }

    void disableAutoInstallUpdates() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
                         L"AutoInstallMinorUpdates", 0, this, L"禁用自动安装更新");
    }

    void setUpdatePolicy(int policy) {
        switch (policy) {
        case 0: // 自动安装更新
            SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                             L"NoAutoUpdate", 0, this, L"设置更新策略");
            SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                             L"AUOptions", 4, this, L"设置更新策略");
            break;
        case 1: // 检查并下载更新
            SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                             L"NoAutoUpdate", 0, this, L"设置更新策略");
            SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                             L"AUOptions", 3, this, L"设置更新策略");
            break;
        case 2: // 仅检查更新
            SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                             L"NoAutoUpdate", 0, this, L"设置更新策略");
            SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                             L"AUOptions", 2, this, L"设置更新策略");
            break;
        case 3: // 从不检查更新
            SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                             L"NoAutoUpdate", 1, this, L"设置更新策略");
            break;
        }
    }

    void disableDefaultShares() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                         L"AutoShareWks", 0, this, L"禁用默认共享");
    }

    void enableDefaultShares() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                         L"AutoShareWks", 1, this, L"启用默认共享");
    }

    void disableFastStartup() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
                         L"HiberbootEnabled", 0, this, L"禁用快速启动");
    }

    void enableFastStartup() {
        SetRegistryDWORD(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
                         L"HiberbootEnabled", 1, this, L"启用快速启动");
    }

    // 启用组策略
    void enableGroupPolicy() {
        // 检查是否已启用
        if (isGroupPolicyEnabled()) {
            QMessageBox::information(this, "组策略", "组策略编辑器已经启用");
            return;
        }

        // 创建批处理文件内容
        const char* batchContent = R"(
            @echo off
            pushd "%~dp0"
            dir /b C:\Windows\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~3*.mum >List.txt
            dir /b C:\Windows\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~3*.mum >>List.txt
            for /f %%i in ('findstr /i . List.txt 2^>nul') do dism /online /norestart /add-package:"C:\Windows\servicing\Packages\%%i"
            pause
        )";

        // 将批处理内容写入临时文件
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring batchFilePath = std::wstring(tempPath) + L"\\enable_gpedit.bat";

        HANDLE hFile = CreateFileW(batchFilePath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            ShowLastError(this, L"创建批处理文件");
            return;
        }

        DWORD bytesWritten;
        WriteFile(hFile, batchContent, (DWORD)strlen(batchContent), &bytesWritten, NULL);
        CloseHandle(hFile);

        // 以管理员身份运行批处理文件
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = batchFilePath.c_str();
        sei.nShow = SW_SHOW;

        if (!ShellExecuteExW(&sei)) {
            ShowLastError(this, L"运行批处理文件");
        } else {
            // 等待批处理完成
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);

            // 删除临时文件
            DeleteFileW(batchFilePath.c_str());

            // 验证是否启用成功
            if (isGroupPolicyEnabled()) {
                // 启用成功后禁用开关
                m_switches["GroupPolicy"]->setEnabled(false);
                QMessageBox::information(this, "操作完成", "组策略编辑器已成功启用");
            } else {
                QMessageBox::warning(this, "操作失败", "组策略编辑器启用失败，请检查系统权限");
            }
        }
    }

private:
    QMap<QString, SwitchButton*> m_switches;
    QButtonGroup *m_policyGroup = nullptr;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // 设置应用程序样式
    //app.setStyle("Fusion");

    // 设置全局字体
    QFont font("Microsoft YaHei", 9);
    app.setFont(font);

    SystemOptimizer optimizer;
    optimizer.show();

    return app.exec();
}

#include "main.moc"
