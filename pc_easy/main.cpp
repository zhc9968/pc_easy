#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QTabWidget>
#include <QGroupBox>
#include <QScrollArea>
#include <QMessageBox>
#include <QProcess>
#include <QDesktopServices>
#include <QUrl>
#include <QStyle>
#include <QFont>
#include <QFontDatabase>
#include <QPalette>
#include <QScreen>
#include <QGuiApplication>
#include <QPropertyAnimation>
#include <QEasingCurve>
#include <QGraphicsDropShadowEffect>
#include <QTimer>
#include <QCloseEvent>
#include <QKeyEvent>
#include <QSettings>
#include <QDir>
#include <QPainter>
#include <QPainterPath>
#include <Windows.h>
#include <tlhelp32.h>
#include <dbt.h>
#include <QAbstractNativeEventFilter>
#include <QMenu>
#include <QAction>
#include <QSystemTrayIcon>
#include <QFormLayout>
#include <QSharedMemory>
#include <QLocalSocket>
#include <QLocalServer>
#include <QWindow>
#include <shellapi.h>

// 检查是否具有管理员权限
bool isRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

// 以管理员权限重新启动程序
bool restartAsAdminRun() {
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);

    SHELLEXECUTEINFOW shellExecuteInfo = {0};
    shellExecuteInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
    shellExecuteInfo.lpVerb = L"runas";
    shellExecuteInfo.lpFile = modulePath;
    shellExecuteInfo.lpParameters = GetCommandLineW();
    shellExecuteInfo.nShow = SW_SHOWNORMAL;
    shellExecuteInfo.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (ShellExecuteExW(&shellExecuteInfo)) {
        WaitForSingleObject(shellExecuteInfo.hProcess, INFINITE);
        CloseHandle(shellExecuteInfo.hProcess);
        return true;
    }

    return false;
}

// 在文件开头添加开关按钮类的定义
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
            // 先断开信号连接，避免触发用户设置的信号槽
            disconnect(this, &SwitchButton::stateChanged, nullptr, nullptr);

            m_state = state;
            updateSliderPosition();
            update();

            // 设置完成后再重新连接信号
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

class TrayIcon : public QSystemTrayIcon {
    Q_OBJECT
public:
    TrayIcon(QObject *parent = nullptr) : QSystemTrayIcon(parent) {
        setIcon(QApplication::windowIcon());
        setToolTip("pc_easy - 多功能系统工具集合");

        // 创建托盘菜单
        QMenu *trayMenu = new QMenu();

        QAction *showMainAction = trayMenu->addAction("显示主窗口");
        QAction *openExplorerAction = trayMenu->addAction("打开资源管理器");
        QAction *openPowerRunAction = trayMenu->addAction("打开运行工具");
        QAction *openScreenManagerAction = trayMenu->addAction("打开窗口管理器");
        QAction *openAutorunAction = trayMenu->addAction("打开自启动管理器");
        QAction *openOptimizerAction = trayMenu->addAction("打开系统优化器");
        trayMenu->addSeparator();
        QAction *exitAction = trayMenu->addAction("退出");

        setContextMenu(trayMenu);

        // 连接信号
        connect(showMainAction, &QAction::triggered, this, &TrayIcon::showMainWindow);
        connect(openExplorerAction, &QAction::triggered, this, &TrayIcon::openExplorer);
        connect(openPowerRunAction, &QAction::triggered, this, &TrayIcon::openPowerRun);
        connect(openScreenManagerAction, &QAction::triggered, this, &TrayIcon::openScreenManager);
        connect(openAutorunAction, &QAction::triggered, this, &TrayIcon::openAutorun);
        connect(openOptimizerAction, &QAction::triggered, this, &TrayIcon::openOptimizer);
        connect(exitAction, &QAction::triggered, this, &TrayIcon::exitApplication);

        // 双击托盘图标显示主窗口
        connect(this, &QSystemTrayIcon::activated, this, [this](ActivationReason reason) {
            if (reason == QSystemTrayIcon::DoubleClick) {
                emit showMainRequested();
            }
        });
    }

signals:
    void showMainRequested();
    void openExplorerRequested();
    void openPowerRunRequested();
    void openScreenManagerRequested();
    void openAutorunRequested();
    void openOptimizerRequested();
    void exitRequested();

private slots:
    void showMainWindow() { emit showMainRequested(); }
    void openExplorer() { emit openExplorerRequested(); }
    void openPowerRun() { emit openPowerRunRequested(); }
    void openScreenManager() { emit openScreenManagerRequested(); }
    void openAutorun() { emit openAutorunRequested(); }
    void openOptimizer() { emit openOptimizerRequested(); }
    void exitApplication() { emit exitRequested(); }
};

// 修改SettingsDialog类，删除快捷键部分，添加新的右键菜单选项
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    SettingsDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("设置");
        setFixedSize(500, 500); // 增加高度以容纳新选项

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        // 检查管理员权限
        bool isAdmin = isRunningAsAdmin();

        // 开机自启动设置组
        QGroupBox *autoStartGroup = new QGroupBox("开机自启动", this);
        QVBoxLayout *autoStartLayout = new QVBoxLayout(autoStartGroup);

        QHBoxLayout *autoStartSwitchLayout = new QHBoxLayout();
        QLabel *autoStartLabel = new QLabel("开机时自动启动 pc_easy", autoStartGroup);
        m_autoStartSwitch = new SwitchButton(autoStartGroup);
        m_autoStartSwitch->setEnabled(isAdmin);

        autoStartSwitchLayout->addWidget(autoStartLabel);
        autoStartSwitchLayout->addStretch();
        autoStartSwitchLayout->addWidget(m_autoStartSwitch);

        autoStartLayout->addLayout(autoStartSwitchLayout);
        if (!isAdmin) {
            autoStartLayout->addWidget(new QLabel("<font color='red'>需要管理员权限才能设置全局自启动</font>", autoStartGroup));
        } else {
            autoStartLayout->addWidget(new QLabel("启用后，pc_easy 将在系统启动时自动运行并最小化到系统托盘", autoStartGroup));
        }

        mainLayout->addWidget(autoStartGroup);

        // 右键菜单设置组 - 修改为三个独立的右键菜单选项
        QGroupBox *contextMenuGroup = new QGroupBox("右键菜单设置", this);
        QVBoxLayout *contextLayout = new QVBoxLayout(contextMenuGroup);

        // 使用pc_easy打开
        QHBoxLayout *openWithLayout = new QHBoxLayout();
        QLabel *openWithLabel = new QLabel("添加'使用pc_easy打开'右键菜单", contextMenuGroup);
        m_openWithSwitch = new SwitchButton(contextMenuGroup);
        m_openWithSwitch->setEnabled(isAdmin);

        openWithLayout->addWidget(openWithLabel);
        openWithLayout->addStretch();
        openWithLayout->addWidget(m_openWithSwitch);
        contextLayout->addLayout(openWithLayout);

        // 高权限运行
        QHBoxLayout *powerRunLayout = new QHBoxLayout();
        QLabel *powerRunLabel = new QLabel("添加'高权限运行'右键菜单", contextMenuGroup);
        m_powerRunSwitch = new SwitchButton(contextMenuGroup);
        m_powerRunSwitch->setEnabled(isAdmin);

        powerRunLayout->addWidget(powerRunLabel);
        powerRunLayout->addStretch();
        powerRunLayout->addWidget(m_powerRunSwitch);
        contextLayout->addLayout(powerRunLayout);

        // 解除文件占用
        QHBoxLayout *unlockLayout = new QHBoxLayout();
        QLabel *unlockLabel = new QLabel("添加'解除文件占用'右键菜单", contextMenuGroup);
        m_unlockSwitch = new SwitchButton(contextMenuGroup);
        m_unlockSwitch->setEnabled(isAdmin);

        unlockLayout->addWidget(unlockLabel);
        unlockLayout->addStretch();
        unlockLayout->addWidget(m_unlockSwitch);
        contextLayout->addLayout(unlockLayout);

        // 权限提示
        if (!isAdmin) {
            contextLayout->addWidget(new QLabel("<font color='red'>需要管理员权限才能设置右键菜单</font>", contextMenuGroup));
        } else {
            contextLayout->addWidget(new QLabel("启用后，在文件或文件夹上右键点击时会出现相应的菜单选项", contextMenuGroup));
        }

        mainLayout->addWidget(contextMenuGroup);
        mainLayout->addStretch();

        // 权限提示
        if (!isAdmin) {
            QLabel *adminWarning = new QLabel("<font color='red'><b>警告：当前程序未以管理员权限运行，部分设置可能无法生效</b></font>");
            adminWarning->setWordWrap(true);
            mainLayout->insertWidget(0, adminWarning);
        }

        // 按钮布局
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *okButton = new QPushButton("确定", this);
        QPushButton *cancelButton = new QPushButton("取消", this);

        buttonLayout->addStretch();
        buttonLayout->addWidget(okButton);
        buttonLayout->addWidget(cancelButton);

        mainLayout->addLayout(buttonLayout);

        // 连接信号
        connect(okButton, &QPushButton::clicked, this, &SettingsDialog::onOkClicked);
        connect(cancelButton, &QPushButton::clicked, this, &SettingsDialog::reject);

        // 从注册表加载设置
        loadSettings();
    }

    bool isAutoStartEnabled() const {
        return m_autoStartSwitch->isChecked();
    }

    bool isOpenWithEnabled() const {
        return m_openWithSwitch->isChecked();
    }

    bool isPowerRunEnabled() const {
        return m_powerRunSwitch->isChecked();
    }

    bool isUnlockEnabled() const {
        return m_unlockSwitch->isChecked();
    }

private slots:
    void onOkClicked() {
        if (!isRunningAsAdmin()) {
            // 检查需要管理员权限的设置
            if ((m_autoStartSwitch->isChecked() && !m_originalAutoStart) ||
                (m_openWithSwitch->isChecked() && !m_originalOpenWith) ||
                (m_powerRunSwitch->isChecked() && !m_originalPowerRun) ||
                (m_unlockSwitch->isChecked() && !m_originalUnlock)) {

                QMessageBox::warning(this, "权限不足",
                                     "需要管理员权限才能设置自启动和右键菜单。\n"
                                     "请以管理员权限重新启动程序。");
                return;
            }
        }

        if (saveSettings()) {
            accept();
        }
    }

private:
    void loadSettings() {
        // 使用全局注册表路径
        QSettings settings("HKEY_LOCAL_MACHINE\\Software\\pc_easy", QSettings::NativeFormat);

        // 先断开所有信号连接，避免触发状态改变信号
        disconnectAllSignals();

        bool autoStart = settings.value("AutoStartEnabled", false).toBool();
        bool openWith = settings.value("OpenWithEnabled", false).toBool();
        bool powerRun = settings.value("PowerRunEnabled", false).toBool();
        bool unlock = settings.value("UnlockEnabled", false).toBool();

        // 保存原始值用于比较
        m_originalAutoStart = autoStart;
        m_originalOpenWith = openWith;
        m_originalPowerRun = powerRun;
        m_originalUnlock = unlock;

        // 使用阻塞信号的方式设置状态
        m_autoStartSwitch->blockSignals(true);
        m_autoStartSwitch->setChecked(autoStart);
        m_autoStartSwitch->blockSignals(false);

        m_openWithSwitch->blockSignals(true);
        m_openWithSwitch->setChecked(openWith);
        m_openWithSwitch->blockSignals(false);

        m_powerRunSwitch->blockSignals(true);
        m_powerRunSwitch->setChecked(powerRun);
        m_powerRunSwitch->blockSignals(false);

        m_unlockSwitch->blockSignals(true);
        m_unlockSwitch->setChecked(unlock);
        m_unlockSwitch->blockSignals(false);

        // 重新连接信号
        reconnectSignals();
    }

    // 断开所有信号连接
    void disconnectAllSignals() {
        disconnect(m_autoStartSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
        disconnect(m_openWithSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
        disconnect(m_powerRunSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
        disconnect(m_unlockSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
    }

    // 重新连接信号
    void reconnectSignals() {
        // 不需要特殊处理，只是防止信号触发
    }

    bool saveSettings() {
        // 使用全局注册表路径
        QSettings settings("HKEY_LOCAL_MACHINE\\Software\\pc_easy", QSettings::NativeFormat);

        // 检查写入权限
        settings.setValue("TestWrite", "test");
        if (settings.status() != QSettings::NoError) {
            QMessageBox::critical(this, "保存失败",
                                  "无法写入全局注册表设置！\n"
                                  "请以管理员权限运行程序。");
            return false;
        }
        settings.remove("TestWrite"); // 删除测试项

        settings.setValue("AutoStartEnabled", m_autoStartSwitch->isChecked());
        settings.setValue("OpenWithEnabled", m_openWithSwitch->isChecked());
        settings.setValue("PowerRunEnabled", m_powerRunSwitch->isChecked());
        settings.setValue("UnlockEnabled", m_unlockSwitch->isChecked());

        // 更新设置
        if (!updateAutoStart(m_autoStartSwitch->isChecked())) {
            QMessageBox::warning(this, "设置失败", "无法设置全局自启动，需要管理员权限。");
            return false;
        }

        if (!updateContextMenu()) {
            QMessageBox::warning(this, "设置失败", "无法设置右键菜单，需要管理员权限。");
            return false;
        }

        return true;
    }

    bool updateAutoStart(bool enabled) {
        if (enabled && !isRunningAsAdmin()) {
            return false;
        }

        // 使用全局自启动路径（所有用户）
        QSettings autoStartSettings("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);

        QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

        if (enabled) {
            autoStartSettings.setValue("pc_easy", "\"" + appPath + "\" -autoRun");
            return (autoStartSettings.status() == QSettings::NoError);
        } else {
            autoStartSettings.remove("pc_easy");
            return true;
        }
    }

    bool updateContextMenu() {
        if ((m_openWithSwitch->isChecked() || m_powerRunSwitch->isChecked() || m_unlockSwitch->isChecked()) &&
            !isRunningAsAdmin()) {
            return false;
        }

        QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
        QString expPath = QDir::toNativeSeparators(QCoreApplication::applicationDirPath() + "/Exp.exe");
        QString powerrunPath = QDir::toNativeSeparators(QCoreApplication::applicationDirPath() + "/PowerRun.exe");

        // 注册表路径（全局）
        QStringList keys = {
            "HKEY_CLASSES_ROOT\\*\\shell",
            "HKEY_CLASSES_ROOT\\Directory\\shell",
            "HKEY_CLASSES_ROOT\\Directory\\Background\\shell"
        };

        // 清理旧的右键菜单
        cleanupOldContextMenu(keys);

        // 添加新的右键菜单
        if (m_openWithSwitch->isChecked()) {
            if (!addContextMenuItem(keys, "pc_easy_open", "使用pc_easy打开",
                                    "\"" + expPath + "\" \"%1\"")) {
                return false;
            }
        }

        if (m_powerRunSwitch->isChecked()) {
            if (!addContextMenuItem(keys, "pc_easy_powerrun", "高权限运行",
                                    "\"" + powerrunPath + "\" \"%1\"")) {
                return false;
            }
        }

        if (m_unlockSwitch->isChecked()) {
            if (!addContextMenuItem(keys, "pc_easy_unlock", "解除文件占用",
                                    "\"" + expPath + "\" \"%1\" unlock")) {
                return false;
            }
        }

        return true;
    }

    void cleanupOldContextMenu(const QStringList& keys) {
        // 清理所有旧的pc_easy相关菜单项
        QStringList oldItems = {"pc_easy", "pc_easy_open", "pc_easy_powerrun", "pc_easy_unlock"};

        for (const QString& key : keys) {
            for (const QString& item : oldItems) {
                QSettings settings(key + "\\" + item, QSettings::NativeFormat);
                settings.remove("");
            }
        }
    }

    bool addContextMenuItem(const QStringList& keys, const QString& itemName,
                            const QString& displayName, const QString& command) {
        for (const QString& key : keys) {
            QSettings settings(key + "\\" + itemName, QSettings::NativeFormat);
            settings.setValue(".", displayName);
            settings.setValue("Icon", QDir::toNativeSeparators(QCoreApplication::applicationFilePath()));

            QSettings commandSettings(key + "\\" + itemName + "\\command", QSettings::NativeFormat);
            commandSettings.setValue(".", command);

            if (settings.status() != QSettings::NoError ||
                commandSettings.status() != QSettings::NoError) {
                return false;
            }
        }
        return true;
    }

    SwitchButton *m_autoStartSwitch;
    SwitchButton *m_openWithSwitch;
    SwitchButton *m_powerRunSwitch;
    SwitchButton *m_unlockSwitch;
    bool m_originalAutoStart = false;
    bool m_originalOpenWith = false;
    bool m_originalPowerRun = false;
    bool m_originalUnlock = false;
};

class DisclaimerDialog : public QDialog {
    Q_OBJECT
public:
    DisclaimerDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("免责声明");
        setWindowFlags(windowFlags() & ~Qt::WindowCloseButtonHint);
        setFixedSize(500, 300);

        QVBoxLayout* layout = new QVBoxLayout(this);

        QLabel* titleLabel = new QLabel("<h3>重要免责声明</h3>");
        titleLabel->setAlignment(Qt::AlignCenter);
        layout->addWidget(titleLabel);

        QTextEdit* textEdit = new QTextEdit();
        textEdit->setHtml(
            "<h2 style='color: #e74c3c;'>⚠️ 重要免责声明</h2>"
            "<p><b>在使用本软件前，请仔细阅读以下内容：</b></p>"
            "<hr>"
            "<h3>📋 使用条款</h3>"
            "<p>1. 本软件仅供学习和合法用途使用</p>"
            "<p>2. 用户需自行承担使用软件带来的所有风险</p>"
            "<p>3. 禁止将本软件用于任何非法目的</p>"
            "<hr>"
            "<h3>⚖️ 责任限制</h3>"
            "<p><b>开发者不对以下情况承担责任：</b></p>"
            "<ul>"
            "<li>因使用本软件导致的系统损坏</li>"
            "<li>数据丢失或文件损坏</li>"
            "<li>系统稳定性问题</li>"
            "<li>任何直接或间接的损失</li>"
            "</ul>"
            "<hr>"
            "<h3>🔒 重要警告</h3>"
            "<p style='color: #c0392b;'><b>高级功能警告：</b></p>"
            "<ul>"
            "<li>文件解锁功能可能造成第三方软件数据未保存或丢失</li>"
            "<li>自启动管理可能影响系统稳定性</li>"
            "<li>权限提升功能需谨慎使用</li>"
            "<li>系统优化设置可能产生不可逆影响</li>"
            "</ul>"
            "<hr>"
            "<p><b>继续使用本软件即表示您同意以上条款，并自愿承担所有风险。</b></p>"
            "<p style='color: #7f8c8d;'>建议在使用前备份重要数据和系统。</p>"
            );
        textEdit->setReadOnly(true);
        layout->addWidget(textEdit);

        QHBoxLayout* btnLayout = new QHBoxLayout();
        m_acceptButton = new QPushButton("我同意 (5)");
        m_acceptButton->setEnabled(false);
        connect(m_acceptButton, &QPushButton::clicked, this, &DisclaimerDialog::accept);

        // 添加不同意按钮
        QPushButton* rejectButton = new QPushButton("不同意");
        connect(rejectButton, &QPushButton::clicked, this, &DisclaimerDialog::onRejectClicked);

        btnLayout->addStretch();
        btnLayout->addWidget(rejectButton); // 先添加不同意按钮
        btnLayout->addWidget(m_acceptButton);
        btnLayout->addStretch();

        layout->addLayout(btnLayout);

        m_timer = new QTimer(this);
        connect(m_timer, &QTimer::timeout, this, &DisclaimerDialog::updateButton);
        m_timer->start(1000);
        m_countdown = 5;
    }

protected:
    void closeEvent(QCloseEvent* event) override {
        event->ignore(); // 阻止关闭
    }

    void keyPressEvent(QKeyEvent* event) override {
        if (event->key() == Qt::Key_F4 && (event->modifiers() & Qt::AltModifier)) {
            event->ignore(); // 阻止Alt+F4
            return;
        }
        QDialog::keyPressEvent(event);
    }

private slots:
    void updateButton() {
        m_countdown--;
        if (m_countdown <= 0) {
            m_timer->stop();
            m_acceptButton->setText("我同意");
            m_acceptButton->setEnabled(true);
        } else {
            m_acceptButton->setText(QString("我同意 (%1)").arg(m_countdown));
        }
    }

    void onRejectClicked() {
        // 确认用户是否真的不同意
        QMessageBox confirmBox;
        confirmBox.setWindowTitle("确认操作");
        confirmBox.setText("<b>您选择了不同意免责声明</b>");
        confirmBox.setInformativeText("此操作将卸载本软件并退出程序。是否确定要卸载？");
        confirmBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        confirmBox.setDefaultButton(QMessageBox::No);
        confirmBox.setIcon(QMessageBox::Question);

        int result = confirmBox.exec();

        if (result == QMessageBox::Yes) {
            // 执行卸载程序
            QString uninstallPath = QDir::currentPath() + "/unins0000.exe";
            if (QFile::exists(uninstallPath)) {
                QProcess::startDetached(uninstallPath);
                QApplication::quit();
            } else {
                exit(0);
            }
        }
        // 如果用户选择No，则不做任何操作，留在当前界面
    }

private:
    QPushButton* m_acceptButton;
    QTimer* m_timer;
    int m_countdown;
};

class ProjectCard : public QWidget {
    Q_OBJECT

public:
    ProjectCard(const QString& title, const QString& description,
                const QString& exePath, QWidget* parent = nullptr)
        : QWidget(parent), m_exePath(exePath) {

        // 使用默认样式
        setFixedSize(320, 220);

        QVBoxLayout* layout = new QVBoxLayout(this);
        layout->setContentsMargins(15, 15, 15, 15);
        layout->setSpacing(8);

        // 标题
        QLabel* titleLabel = new QLabel(title);
        titleLabel->setWordWrap(true);
        titleLabel->setMaximumHeight(40);
        layout->addWidget(titleLabel);

        // 描述
        QTextEdit* descText = new QTextEdit();
        descText->setPlainText(description);
        descText->setReadOnly(true);
        descText->setFixedHeight(80);
        layout->addWidget(descText);

        // 按钮布局
        QHBoxLayout* buttonLayout = new QHBoxLayout();

        // 启动按钮
        QPushButton* startBtn = new QPushButton("启动工具");
        startBtn->setFixedHeight(30);
        connect(startBtn, &QPushButton::clicked, this, &ProjectCard::startApplication);

        // 详细信息按钮
        QPushButton* infoBtn = new QPushButton("详细信息");
        infoBtn->setFixedHeight(30);
        connect(infoBtn, &QPushButton::clicked, this, &ProjectCard::showInfo);

        buttonLayout->addWidget(startBtn);
        buttonLayout->addWidget(infoBtn);
        layout->addLayout(buttonLayout);

        layout->addStretch();
    }

    void setIndex(int index) { m_index = index; }

signals:
    void infoRequested(int index);

private slots:
    void startApplication() {
        QProcess* process = new QProcess(this);
        process->start(m_exePath);

        if (!process->waitForStarted(3000)) {
            QMessageBox::warning(this, "启动失败",
                                 QString("无法启动程序: %1\n请检查文件是否存在").arg(m_exePath));
        }
    }

    void showInfo() {
        emit infoRequested(m_index);
    }

private:
    QString m_exePath;
    int m_index = 0;
};

// 修改MainWindow类，删除快捷键相关代码
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(bool autoRun = false, QWidget* parent = nullptr)
        : QMainWindow(parent), m_autoRun(autoRun) {
        setupUI();
        setupConnections();
        m_trayIcon->show();

        // 显示管理员权限状态
        if (isRunningAsAdmin()) {
            setWindowTitle("pc_easy - 多功能系统工具集合 [管理员]");
        }

        // 如果是自启动模式，最小化到托盘
        if (m_autoRun) {
            hide();
        }
    }

    void activateWindow() {
        HWND hwnd = (HWND)winId();
        if (hwnd) {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        }
    }

    ~MainWindow() {
        // 删除快捷键相关的清理代码
    }

private:
    QVector<ProjectCard*> m_projectCards;
    bool m_autoRun;
    TrayIcon *m_trayIcon;
    QPushButton* settingsBtn;

    void setupUI() {
        setWindowTitle("pc_easy - 多功能系统工具集合");
        setMinimumSize(800, 500);

        // 设置窗口图标
        setWindowIcon(QApplication::style()->standardIcon(QStyle::SP_ComputerIcon));

        // 中央部件
        QWidget* centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);

        QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);

        // 权限状态显示
        if (!isRunningAsAdmin()) {
            QLabel* adminWarning = new QLabel("<font color='red'><b>⚠️ 当前未以管理员权限运行，部分功能可能受限</b></font>");
            adminWarning->setAlignment(Qt::AlignCenter);
            mainLayout->addWidget(adminWarning);
        }

        // 标题
        QLabel* titleLabel = new QLabel("pc_easy");
        titleLabel->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(titleLabel);

        // 副标题
        QLabel* subtitleLabel = new QLabel("多功能系统工具集合");
        subtitleLabel->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(subtitleLabel);

        // 项目卡片容器
        QScrollArea* scrollArea = new QScrollArea;
        scrollArea->setWidgetResizable(true);

        QWidget* cardsContainer = new QWidget;
        QGridLayout* gridLayout = new QGridLayout(cardsContainer);
        gridLayout->setAlignment(Qt::AlignCenter);

        // 创建项目卡片
        createProjectCards(gridLayout);

        scrollArea->setWidget(cardsContainer);
        mainLayout->addWidget(scrollArea, 1);

        // 在底部按钮布局中添加退出按钮
        QHBoxLayout* buttonLayout = new QHBoxLayout;
        buttonLayout->setSpacing(15);

        QPushButton* aboutBtn = new QPushButton("关于我们");
        aboutBtn->setFixedSize(100, 30);

        QPushButton* disclaimerBtn = new QPushButton("免责声明");
        disclaimerBtn->setFixedSize(100, 30);

        settingsBtn = new QPushButton("设置");
        settingsBtn->setFixedSize(100, 30);

        // 添加重新启动为管理员按钮
        QPushButton* adminBtn = new QPushButton("重新启动(管理员)");
        adminBtn->setFixedSize(120, 30);
        connect(adminBtn, &QPushButton::clicked, this, &MainWindow::restartAsAdmin);

        // 添加退出按钮
        QPushButton* exitBtn = new QPushButton("退出程序");
        exitBtn->setFixedSize(100, 30);
        connect(exitBtn, &QPushButton::clicked, this, &MainWindow::exitApplication);

        buttonLayout->addStretch();
        buttonLayout->addWidget(aboutBtn);
        buttonLayout->addWidget(disclaimerBtn);
        buttonLayout->addWidget(settingsBtn);
        buttonLayout->addWidget(adminBtn);
        buttonLayout->addWidget(exitBtn);
        buttonLayout->addStretch();

        mainLayout->addLayout(buttonLayout);

        // 连接信号
        connect(aboutBtn, &QPushButton::clicked, this, &MainWindow::showAboutDialog);
        connect(disclaimerBtn, &QPushButton::clicked, this, &MainWindow::showDisclaimerDialog);

        // 创建系统托盘图标
        m_trayIcon = new TrayIcon(this);

        // 连接托盘信号
        connect(m_trayIcon, &TrayIcon::showMainRequested, this, &MainWindow::showNormal);
        connect(m_trayIcon, &TrayIcon::openExplorerRequested, this, [this]() {
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/Exp.exe");
        });
        connect(m_trayIcon, &TrayIcon::openPowerRunRequested, this, [this]() {
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/PowerRun.exe");
        });
        connect(m_trayIcon, &TrayIcon::openScreenManagerRequested, this, [this]() {
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/screen_ok.exe");
        });
        connect(m_trayIcon, &TrayIcon::openAutorunRequested, this, [this]() {
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/AutorunManager.exe");
        });
        connect(m_trayIcon, &TrayIcon::openOptimizerRequested, this, [this]() {
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/SysOptimizer.exe");
        });
        connect(m_trayIcon, &TrayIcon::exitRequested, this, &MainWindow::exitApplication);

        // 删除快捷键相关代码
    }

    void createProjectCards(QGridLayout* layout) {
        m_projectCards.clear();

        // 项目1: 文件资源管理器
        ProjectCard* project1 = new ProjectCard(
            "高级文件资源管理器",
            "基于TrustedInstaller权限的超级文件管理器，具备专业级文件操作能力。支持NTFS数据流编辑、文件属性深度修改、文件占用强制解锁等功能。",
            "exp.exe"
            );
        project1->setIndex(0);
        layout->addWidget(project1, 0, 0);
        m_projectCards.append(project1);

        // 项目2: 自启动管理器
        ProjectCard* project2 = new ProjectCard(
            "系统自启动管理器",
            "全面深度扫描Windows启动项的专业管理工具。覆盖注册表启动项、Wow64架构程序、Winlogon系统关键启动项等所有启动位置。",
            "AutorunManager.exe"
            );
        project2->setIndex(1);
        layout->addWidget(project2, 0, 1);
        m_projectCards.append(project2);

        // 项目3: 权限运行工具
        ProjectCard* project3 = new ProjectCard(
            "多权限运行工具",
            "六层级权限控制系统，从普通权限到系统内核的完整权限管理。支持普通用户、管理员、SYSTEM、TrustedInstaller和上帝模式。",
            "powerrun.exe"
            );
        project3->setIndex(2);
        layout->addWidget(project3, 1, 0);
        m_projectCards.append(project3);

        // 项目4: 窗口管理工具
        ProjectCard* project4 = new ProjectCard(
            "高级窗口管理器",
            "专业级窗口调试和管理工具，支持实时窗口属性修改。包含窗口样式深度修改、透明度层级调整、进程优先级控制等功能。",
            "screen_ok.exe"
            );
        project4->setIndex(3);
        layout->addWidget(project4, 1, 1);
        m_projectCards.append(project4);

        // 项目5: 系统优化器
        ProjectCard* project5 = new ProjectCard(
            "一站式系统优化器",
            "Windows系统深度优化和安全性配置工具集。包含安全加固、性能优化、界面定制、隐私保护等全方位优化模块。",
            "SysOptimizer.exe"
            );
        project5->setIndex(4);
        layout->addWidget(project5, 2, 0);
        m_projectCards.append(project5);
    }

    void setupConnections() {
        // 连接所有卡片的详细信息信号
        for (ProjectCard* card : m_projectCards) {
            connect(card, &ProjectCard::infoRequested, this, &MainWindow::showProjectInfo);
        }
        // 添加设置按钮连接
        connect(settingsBtn, &QPushButton::clicked, this, &MainWindow::showSettingsDialog);
        // 修改托盘退出信号连接
        connect(m_trayIcon, &TrayIcon::exitRequested, this, &MainWindow::exitApplication);
    }

private slots:
    void showSettingsDialog() {
        SettingsDialog dlg(this);
        dlg.exec();
    }

    void restartAsAdmin() {
        if (isRunningAsAdmin()) {
            QMessageBox::information(this, "提示", "程序已经在管理员权限下运行。");
            return;
        }

        QMessageBox::StandardButton reply = QMessageBox::question(this, "重新启动",
                                                                  "需要重新启动程序以获得管理员权限。\n是否继续？",
                                                                  QMessageBox::Yes | QMessageBox::No);

        if (reply == QMessageBox::Yes) {
            if (restartAsAdminRun()) {
                QApplication::quit();
            } else {
                QMessageBox::critical(this, "错误", "无法以管理员权限重新启动程序。");
            }
        }
    }

    // 添加退出处理函数
    void exitApplication() {
        // 确认退出
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "确认退出",
                                      "确定要退出 pc_easy 吗？",
                                      QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            // 清理资源
            m_trayIcon->hide(); // 隐藏托盘图标
            QApplication::quit(); // 退出应用程序
        }
    }

    // 修改关闭事件处理
    void closeEvent(QCloseEvent *event) override {
        if (m_trayIcon->isVisible()) {
            // 最小化到托盘而不是退出
            hide();
            event->ignore();
        } else {
            // 如果托盘不可用，直接退出
            QMainWindow::closeEvent(event);
        }
    }

    void showAboutDialog() {
        QString adminStatus = isRunningAsAdmin() ? "是" : "否";

        QMessageBox::about(this, "关于 pc_easy",
                           "<h2>pc_easy v2.3</h2>"
                           "<p><b>多功能系统工具集合</b></p>"
                           "<p><b>管理员权限:</b> " + adminStatus + "</p>"
                                               "<p>本工具集成了五个实用的系统工具：</p>"
                                               "<ul>"
                                               "<li><b>高级文件资源管理器</b> - 强大的文件管理和解锁工具</li>"
                                               "<li><b>系统自启动管理器</b> - 全面的启动项管理</li>"
                                               "<li><b>多权限运行工具</b> - 多种权限级别运行程序</li>"
                                               "<li><b>高级窗口管理器</b> - 专业的窗口管理</li>"
                                               "<li><b>一站式系统优化器</b> - 系统优化和安全设置</li>"
                                               "</ul>"
                                               "<p><b>右键菜单功能：</b></p>"
                                               "<ul>"
                                               "<li><b>使用pc_easy打开</b> - 使用文件资源管理器打开文件/文件夹</li>"
                                               "<li><b>高权限运行</b> - 以管理员权限运行程序</li>"
                                               "<li><b>解除文件占用</b> - 强制解锁被占用的文件</li>"
                                               "</ul>"
                                               "<p><b>开发信息：</b></p>"
                                               "<p>• 基于 Qt 6.8 开发</p>"
                                               "<p>• 支持 Windows 10/11 系统</p>"
                                               "<p>• 开源项目</p>"
                                               "<hr>"
                                               "<p>© 2025 zhc9968(个人) - 保留所有权利</p>");
    }

    void showDisclaimerDialog() {
        QMessageBox::critical(this, "重要免责声明",
                              "<h2 style='color: #e74c3c;'>⚠️ 重要免责声明</h2>"
                              "<p><b>在使用本软件前，请仔细阅读以下内容：</b></p>"
                              "<hr>"
                              "<h3>📋 使用条款</h3>"
                              "<p>1. 本软件仅供学习和合法用途使用</p>"
                              "<p>2. 用户需自行承担使用软件带来的所有风险</p>"
                              "<p>3. 禁止将本软件用于任何非法目的</p>"
                              "<hr>"
                              "<h3>⚖️ 责任限制</h3>"
                              "<p><b>开发者不对以下情况承担责任：</b></p>"
                              "<ul>"
                              "<li>因使用本软件导致的系统损坏</li>"
                              "<li>数据丢失或文件损坏</li>"
                              "<li>系统稳定性问题</li>"
                              "<li>任何直接或间接的损失</li>"
                              "</ul>"
                              "<hr>"
                              "<h3>🔒 重要警告</h3>"
                              "<p style='color: #c0392b;'><b>高级功能警告：</b></p>"
                              "<ul>"
                              "<li>文件解锁功能可能造成第三方软件数据未保存或丢失</li>"
                              "<li>自启动管理可能影响系统稳定性</li>"
                              "<li>权限提升功能需谨慎使用</li>"
                              "<li>系统优化设置可能产生不可逆影响</li>"
                              "</ul>"
                              "<hr>"
                              "<p><b>继续使用本软件即表示您同意以上条款，并自愿承担所有风险。</b></p>"
                              "<p style='color: #7f8c8d;'>建议在使用前备份重要数据和系统。</p>");
    }

    void showProjectInfo(int index) {
        QStringList titles = {
            "高级文件资源管理器 - 技术规格",
            "系统自启动管理器 - 技术规格",
            "多权限运行工具 - 技术规格",
            "高级窗口管理器 - 技术规格",
            "一站式系统优化器 - 技术规格"
        };

        QStringList descriptions = {
            // 文件资源管理器详细描述
            "<h3>高级文件资源管理器</h3>"
            "<p><b>基于TrustedInstaller权限的超级文件管理解决方案</b></p>"
            "<hr>"
            "<h4>核心技术特性：</h4>"
            "<ul>"
            "<li><b>TrustedInstaller权限集成</b> - 突破系统文件访问限制</li>"
            "<li><b>NTFS数据流编辑器</b> - 支持Zone.Identifier等元数据编辑</li>"
            "<li><b>文件属性深度控制</b> - 32种文件属性精确调整</li>"
            "<li><b>进程占用分析</b> - 使用系统句柄表枚举</li>"
            "<li><b>文件解锁功能</b> - 强制解除文件占用</li>"
            "</ul>",

            // 自启动管理器详细描述
            "<h3>系统自启动管理器</h3>"
            "<p><b>全面深度扫描Windows启动项的专业管理工具</b></p>"
            "<hr>"
            "<h4>扫描覆盖范围：</h4>"
            "<ul>"
            "<li><b>12个注册表关键路径</b> - 完整覆盖所有自启动位置</li>"
            "<li><b>Wow64架构支持</b> - 32/64位程序全面检测</li>"
            "<li><b>Winlogon项检测</b> - 系统关键启动项监控</li>"
            "<li><b>启动文件夹分析</b> - 快捷方式和直接执行文件</li>"
            "</ul>"
            "<h4>安全验证功能：</h4>"
            "<ul>"
            "<li>数字签名证书链验证</li>"
            "<li>系统关键项安全警告</li>"
            "</ul>",

            // 权限运行工具详细描述
            "<h3>多权限运行工具</h3>"
            "<p><b>六层级权限控制系统，从普通用户到系统内核的完整权限管理</b></p>"
            "<hr>"
            "<h4>六层级权限架构：</h4>"
            "<ul>"
            "<li><b>Level 1</b> - 普通用户（标准UAC）</li>"
            "<li><b>Level 2</b> - 管理员权限</li>"
            "<li><b>Level 3</b> - SYSTEM系统权限</li>"
            "<li><b>Level 4</b> - TrustedInstaller权限</li>"
            "<li><b>Level 5</b> - 上帝模式（最高完整性令牌）</li>"
            "</ul>"
            "<h4>技术实现：</h4>"
            "<ul>"
            "<li>令牌复制和权限提升</li>"
            "<li>完整性级别调整</li>"
            "</ul>",

            // 窗口管理工具详细描述
            "<h3>高级窗口管理器</h3>"
            "<p><b>专业级窗口调试和管理工具，支持实时窗口属性修改</b></p>"
            "<hr>"
            "<h4>窗口控制能力：</h4>"
            "<ul>"
            "<li><b>200+窗口样式属性</b> - 完整WS_*和WS_EX_*控制</li>"
            "<li><b>实时属性监控</b> - 动态跟踪窗口状态变化</li>"
            "<li><b>热键操作系统</b> - Win+Alt快速操作组合</li>"
            "<li><b>进程关联管理</b> - 窗口与进程关系分析</li>"
            "</ul>",

            // 系统优化器详细描述
            "<h3>一站式系统优化器</h3>"
            "<p><b>Windows系统深度优化和安全性配置工具集</b></p>"
            "<hr>"
            "<h4>优化模块分类：</h4>"
            "<ul>"
            "<li><b>安全加固</b> - 防火墙、安全警告、SmartScreen配置</li>"
            "<li><b>性能优化</b> - 服务调整、系统启动调整</li>"
            "<li><b>界面定制</b> - 资源管理器、桌面个性化</li>"
            "</ul>"
            "<h4>特色功能：</h4>"
            "<ul>"
            "<li>Windows家庭版组策略启用</li>"
            "<li>Windows11右键菜单关闭</li>"
            "</ul>"
        };

        if (index >= 0 && index < titles.size()) {
            QMessageBox msgBox;
            msgBox.setWindowTitle(titles[index]);
            msgBox.setText(descriptions[index]);
            msgBox.setIcon(QMessageBox::Information);
            msgBox.exec();
        }
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // 设置应用程序属性
    app.setApplicationName("pc_easy");
    app.setApplicationVersion("2.3");
    app.setOrganizationName("zhc9968_pc_easy");
    app.setQuitOnLastWindowClosed(false); // 允许在没有窗口时保持运行

    // 设置应用程序图标
    app.setWindowIcon(QApplication::style()->standardIcon(QStyle::SP_ComputerIcon));

    // 设置全局字体
    QFont font("Microsoft YaHei", 10);
    app.setFont(font);

    // 检查命令行参数
    bool autoRun = false;
    bool forceNewInstance = false;

    for (int i = 1; i < argc; ++i) {
        QString arg = QString(argv[i]);
        if (arg == "-autoRun") {
            autoRun = true;
        } else if (arg == "-force") {
            forceNewInstance = true;
        }
    }

    // 检查管理员权限，如果不是管理员且不是强制新实例，则请求提权
    if (!isRunningAsAdmin() && !forceNewInstance) {
        QMessageBox::StandardButton reply = QMessageBox::question(nullptr, "权限提示",
                                                                  "pc_easy 需要管理员权限才能完整运行所有功能。\n"
                                                                  "是否以管理员权限重新启动程序？\n\n"
                                                                  "选择\"否\"将以普通权限运行，但部分功能可能受限。",
                                                                  QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel,
                                                                  QMessageBox::Yes);

        if (reply == QMessageBox::Yes) {
            if (restartAsAdminRun()) {
                return 0; // 退出当前实例
            } else {
                QMessageBox::warning(nullptr, "警告",
                                     "无法以管理员权限重新启动程序。\n"
                                     "程序将以普通权限运行，部分功能可能受限。");
            }
        } else if (reply == QMessageBox::Cancel) {
            return 0; // 用户取消，退出程序
        }
    }

    // 设置应用程序唯一标识
    const QString appId = isRunningAsAdmin() ? "pc_easy_instance_admin" : "pc_easy_instance";

    // 单实例检查（除非强制新实例）
    QSharedMemory sharedMemory;
    sharedMemory.setKey(appId);

    if (!forceNewInstance && sharedMemory.attach()) {
        QMessageBox::information(nullptr, "提示",
                                 isRunningAsAdmin() ?
                                     "pc_easy已经在运行（管理员模式），你可以在系统托盘中找到他。" :
                                     "pc_easy已经在运行（普通模式），你可以在系统托盘中找到他。");
        return 0; // 退出新实例
    }

    // 创建共享内存并锁定
    if (!sharedMemory.create(1)) {
        QMessageBox::critical(nullptr, "错误",
                              "无法创建共享内存段！\n"
                              "程序可能无法正常运行。");
        return 1;
    }

    // 创建本地服务器用于接收激活请求
    QLocalServer server;
    if (!server.listen(appId)) {
        QMessageBox::warning(nullptr, "警告",
                             "无法创建本地服务器！\n"
                             "单实例功能可能受限。");
    }

    // 检查注册表判断是否需要显示免责声明（使用全局注册表）
    QSettings settings("HKEY_LOCAL_MACHINE\\Software\\pc_easy", QSettings::NativeFormat);
    bool disclaimerAgreed = settings.value("disclaimerHasBeenAgreed", false).toBool();

    // 如果全局注册表无法访问，尝试用户注册表
    if (settings.status() != QSettings::NoError) {
        QSettings userSettings("HKEY_CURRENT_USER\\Software\\pc_easy", QSettings::NativeFormat);
        disclaimerAgreed = userSettings.value("disclaimerHasBeenAgreed", false).toBool();
    }

    if (!disclaimerAgreed) {
        DisclaimerDialog dlg;
        if (dlg.exec() == QDialog::Accepted) {
            // 用户同意后设置注册表值（优先尝试全局注册表）
            settings.setValue("disclaimerHasBeenAgreed", true);
            if (settings.status() != QSettings::NoError) {
                QSettings userSettings("HKEY_CURRENT_USER\\Software\\pc_easy", QSettings::NativeFormat);
                userSettings.setValue("disclaimerHasBeenAgreed", true);
            }
        } else {
            // 用户不同意则退出程序
            return 0;
        }
    }

    // 检查系统托盘是否可用
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        QMessageBox::critical(nullptr, "系统错误",
                              "您的系统不支持托盘图标功能！\n\n"
                              "程序将无法在后台运行。\n"
                              "是否继续运行程序？",
                              QMessageBox::Yes | QMessageBox::No);

        // 如果用户选择不继续，退出程序
        if (QMessageBox::No) {
            return 0;
        }
    }

    // 创建并显示主窗口
    MainWindow window(autoRun);

    // 如果托盘不可用，强制显示主窗口
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        window.show();
    } else if (!autoRun) {
        window.show();
    }

    // 运行应用程序
    int result = app.exec();

    // 程序退出时清理共享内存
    sharedMemory.detach();

    return result;
}

#include "main.moc"
