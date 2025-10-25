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

// 低级键盘钩子管理器类
class KeyboardHook : public QObject, public QAbstractNativeEventFilter {
    Q_OBJECT
public:
    static KeyboardHook* instance() {
        static KeyboardHook instance;
        return &instance;
    }

    bool registerShortcut(UINT modifiers, UINT key, const QString& identifier) {
        if (m_hook) return true; // 钩子已经安装

        m_hook = SetWindowsHookEx(WH_KEYBOARD_LL, lowLevelKeyboardProc, GetModuleHandle(NULL), 0);
        if (!m_hook) {
            qWarning() << "Failed to install keyboard hook:" << GetLastError();
            return false;
        }

        m_shortcuts.insert(qMakePair(modifiers, key), identifier);
        return true;
    }

    void unregisterShortcut(UINT modifiers, UINT key) {
        m_shortcuts.remove(qMakePair(modifiers, key));

        if (m_shortcuts.isEmpty() && m_hook) {
            UnhookWindowsHookEx(m_hook);
            m_hook = NULL;
        }
    }

    void unregisterAll() {
        m_shortcuts.clear();
        if (m_hook) {
            UnhookWindowsHookEx(m_hook);
            m_hook = NULL;
        }
    }

    // 修改方法签名
    bool nativeEventFilter(const QByteArray &eventType, void *message, qintptr *result) override {
        Q_UNUSED(eventType);
        Q_UNUSED(result);

        MSG* msg = static_cast<MSG*>(message);
        if (msg->message == WM_KEYDOWN || msg->message == WM_SYSKEYDOWN) {
            UINT vkCode = static_cast<UINT>(msg->wParam);
            UINT modifiers = 0;

            if (GetKeyState(VK_CONTROL) & 0x8000) modifiers |= MOD_CONTROL;
            if (GetKeyState(VK_SHIFT) & 0x8000) modifiers |= MOD_SHIFT;
            if (GetKeyState(VK_MENU) & 0x8000) modifiers |= MOD_ALT;
            if (GetKeyState(VK_LWIN) & 0x8000 || GetKeyState(VK_RWIN) & 0x8000) modifiers |= MOD_WIN;

            QPair<UINT, UINT> keyCombo(modifiers, vkCode);
            if (m_shortcuts.contains(keyCombo)) {
                emit shortcutTriggered(m_shortcuts[keyCombo]);
                return true;
            }
        }
        return false;
    }

signals:
    void shortcutTriggered(const QString& identifier);

private:
    KeyboardHook() : m_hook(NULL) {
        qApp->installNativeEventFilter(this);
    }

    ~KeyboardHook() {
        unregisterAll();
    }

    static LRESULT CALLBACK lowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode == HC_ACTION) {
            KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                UINT vkCode = pKeyBoard->vkCode;
                UINT modifiers = 0;

                if (GetKeyState(VK_CONTROL) & 0x8000) modifiers |= MOD_CONTROL;
                if (GetKeyState(VK_SHIFT) & 0x8000) modifiers |= MOD_SHIFT;
                if (GetKeyState(VK_MENU) & 0x8000) modifiers |= MOD_ALT;
                if (GetKeyState(VK_LWIN) & 0x8000 || GetKeyState(VK_RWIN) & 0x8000) modifiers |= MOD_WIN;

                QPair<UINT, UINT> keyCombo(modifiers, vkCode);
                if (instance()->m_shortcuts.contains(keyCombo)) {
                    emit instance()->shortcutTriggered(instance()->m_shortcuts[keyCombo]);
                    return 1; // 阻止事件传递
                }
            }
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    HHOOK m_hook;
    QMap<QPair<UINT, UINT>, QString> m_shortcuts;
};

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
        QAction *openScreenManagerAction = trayMenu->addAction("打开窗口管理器"); // 新增
        QAction *openAutorunAction = trayMenu->addAction("打开自启动管理器");
        QAction *openOptimizerAction = trayMenu->addAction("打开系统优化器");
        trayMenu->addSeparator();
        QAction *exitAction = trayMenu->addAction("退出");

        setContextMenu(trayMenu);

        // 连接信号
        connect(showMainAction, &QAction::triggered, this, &TrayIcon::showMainWindow);
        connect(openExplorerAction, &QAction::triggered, this, &TrayIcon::openExplorer);
        connect(openPowerRunAction, &QAction::triggered, this, &TrayIcon::openPowerRun);
        connect(openScreenManagerAction, &QAction::triggered, this, &TrayIcon::openScreenManager); // 新增
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
    void openScreenManagerRequested(); // 新增
    void openAutorunRequested();
    void openOptimizerRequested();
    void exitRequested();

private slots:
    void showMainWindow() { emit showMainRequested(); }
    void openExplorer() { emit openExplorerRequested(); }
    void openPowerRun() { emit openPowerRunRequested(); }
    void openScreenManager() { emit openScreenManagerRequested(); } // 新增
    void openAutorun() { emit openAutorunRequested(); }
    void openOptimizer() { emit openOptimizerRequested(); }
    void exitApplication() { emit exitRequested(); }
};

// 修改SettingsDialog类
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    SettingsDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("设置");
        setFixedSize(500, 400);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        // 开机自启动设置组
        QGroupBox *autoStartGroup = new QGroupBox("开机自启动", this);
        QVBoxLayout *autoStartLayout = new QVBoxLayout(autoStartGroup);

        QHBoxLayout *autoStartSwitchLayout = new QHBoxLayout();
        QLabel *autoStartLabel = new QLabel("开机时自动启动 pc_easy", autoStartGroup);
        m_autoStartSwitch = new SwitchButton(autoStartGroup);

        autoStartSwitchLayout->addWidget(autoStartLabel);
        autoStartSwitchLayout->addStretch();
        autoStartSwitchLayout->addWidget(m_autoStartSwitch);

        autoStartLayout->addLayout(autoStartSwitchLayout);
        autoStartLayout->addWidget(new QLabel("启用后，pc_easy 将在系统启动时自动运行并最小化到系统托盘", autoStartGroup));

        mainLayout->addWidget(autoStartGroup);

        // 快捷键设置组
        QGroupBox *shortcutGroup = new QGroupBox("全局快捷键", this);
        QFormLayout *shortcutLayout = new QFormLayout(shortcutGroup);

        // 资源管理器快捷键
        QHBoxLayout *explorerShortcutLayout = new QHBoxLayout();
        m_explorerShortcutSwitch = new SwitchButton(shortcutGroup);
        QLabel *explorerLabel = new QLabel("Ctrl + Win + E - 打开资源管理器", shortcutGroup);

        explorerShortcutLayout->addWidget(m_explorerShortcutSwitch);
        explorerShortcutLayout->addWidget(explorerLabel);
        shortcutLayout->addRow("资源管理器:", explorerShortcutLayout);

        // 运行工具快捷键
        QHBoxLayout *powerrunShortcutLayout = new QHBoxLayout();
        m_powerrunShortcutSwitch = new SwitchButton(shortcutGroup);
        QLabel *powerrunLabel = new QLabel("Ctrl + Win + R - 打开运行工具", shortcutGroup);

        powerrunShortcutLayout->addWidget(m_powerrunShortcutSwitch);
        powerrunShortcutLayout->addWidget(powerrunLabel);
        shortcutLayout->addRow("运行工具:", powerrunShortcutLayout);

        mainLayout->addWidget(shortcutGroup);

        // 右键菜单设置组
        QGroupBox *contextMenuGroup = new QGroupBox("右键菜单设置", this);
        QVBoxLayout *contextLayout = new QVBoxLayout(contextMenuGroup);

        QHBoxLayout *contextSwitchLayout = new QHBoxLayout();
        QLabel *contextLabel = new QLabel("在资源管理器右键菜单中添加'使用pc_easy打开'", contextMenuGroup);
        m_contextMenuSwitch = new SwitchButton(contextMenuGroup);

        contextSwitchLayout->addWidget(contextLabel);
        contextSwitchLayout->addStretch();
        contextSwitchLayout->addWidget(m_contextMenuSwitch);

        contextLayout->addLayout(contextSwitchLayout);
        contextLayout->addWidget(new QLabel("启用后，在文件或文件夹上右键点击时会出现'使用pc_easy打开'选项", contextMenuGroup));

        mainLayout->addWidget(contextMenuGroup);
        mainLayout->addStretch();

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

    bool isExplorerShortcutEnabled() const {
        return m_explorerShortcutSwitch->isChecked();
    }

    bool isPowerrunShortcutEnabled() const {
        return m_powerrunShortcutSwitch->isChecked();
    }

    bool isContextMenuEnabled() const {
        return m_contextMenuSwitch->isChecked();
    }

private slots:
    void onOkClicked() {
        saveSettings();
        accept();
    }

private:
    void loadSettings() {
        QSettings settings("HKEY_CURRENT_USER\\Software\\pc_easy", QSettings::NativeFormat);

        // 先断开所有信号连接，避免触发状态改变信号
        disconnectAllSignals();

        bool autoStart = settings.value("AutoStartEnabled", false).toBool();
        bool explorerShortcut = settings.value("ExplorerShortcutEnabled", false).toBool();
        bool powerrunShortcut = settings.value("PowerrunShortcutEnabled", false).toBool();
        bool contextMenu = settings.value("ContextMenuEnabled", false).toBool();

        // 使用阻塞信号的方式设置状态
        m_autoStartSwitch->blockSignals(true);
        m_autoStartSwitch->setChecked(autoStart);
        m_autoStartSwitch->blockSignals(false);

        m_explorerShortcutSwitch->blockSignals(true);
        m_explorerShortcutSwitch->setChecked(explorerShortcut);
        m_explorerShortcutSwitch->blockSignals(false);

        m_powerrunShortcutSwitch->blockSignals(true);
        m_powerrunShortcutSwitch->setChecked(powerrunShortcut);
        m_powerrunShortcutSwitch->blockSignals(false);

        m_contextMenuSwitch->blockSignals(true);
        m_contextMenuSwitch->setChecked(contextMenu);
        m_contextMenuSwitch->blockSignals(false);

        // 重新连接信号
        reconnectSignals();
    }

    // 断开所有信号连接
    void disconnectAllSignals() {
        disconnect(m_autoStartSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
        disconnect(m_explorerShortcutSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
        disconnect(m_powerrunShortcutSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
        disconnect(m_contextMenuSwitch, &SwitchButton::stateChanged, nullptr, nullptr);
    }

    // 重新连接信号
    void reconnectSignals() {
        connect(m_explorerShortcutSwitch, &SwitchButton::stateChanged, this, [this](bool state) {
            // 这里只是预览，不会立即注册
            // 实际注册在 saveSettings() 中处理
        });
        connect(m_powerrunShortcutSwitch, &SwitchButton::stateChanged, this, [this](bool state) {
            // 这里只是预览，不会立即注册
            // 实际注册在 saveSettings() 中处理
        });
        connect(m_contextMenuSwitch, &SwitchButton::stateChanged, this, &SettingsDialog::updateContextMenu);
    }

    void saveSettings() {
        QSettings settings("HKEY_CURRENT_USER\\Software\\pc_easy", QSettings::NativeFormat);
        settings.setValue("AutoStartEnabled", m_autoStartSwitch->isChecked());
        settings.setValue("ExplorerShortcutEnabled", m_explorerShortcutSwitch->isChecked());
        settings.setValue("PowerrunShortcutEnabled", m_powerrunShortcutSwitch->isChecked());
        settings.setValue("ContextMenuEnabled", m_contextMenuSwitch->isChecked());

        updateAutoStart(m_autoStartSwitch->isChecked());
        updateContextMenu(m_contextMenuSwitch->isChecked());

        // 只在保存设置时才真正注册/注销快捷键
        if (m_explorerShortcutSwitch->isChecked()) {
            KeyboardHook::instance()->registerShortcut(MOD_CONTROL | MOD_WIN, 'E', "explorer");
        } else {
            KeyboardHook::instance()->unregisterShortcut(MOD_CONTROL | MOD_WIN, 'E');
        }

        if (m_powerrunShortcutSwitch->isChecked()) {
            KeyboardHook::instance()->registerShortcut(MOD_CONTROL | MOD_WIN, 'R', "powerrun");
        } else {
            KeyboardHook::instance()->unregisterShortcut(MOD_CONTROL | MOD_WIN, 'R');
        }
    }

    void updateAutoStart(bool enabled) {
        QSettings autoStartSettings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);

        QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

        if (enabled) {
            autoStartSettings.setValue("pc_easy", "\"" + appPath + "\" -autoRun");
        } else {
            autoStartSettings.remove("pc_easy");
        }
    }

    void updateContextMenu(bool enabled) {
        QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
        QString expPath = QDir::toNativeSeparators(QCoreApplication::applicationDirPath() + "/Exp.exe");

        // 注册表路径
        QStringList keys = {
            "HKEY_CLASSES_ROOT\\*\\shell\\pc_easy",
            "HKEY_CLASSES_ROOT\\Directory\\shell\\pc_easy",
            "HKEY_CLASSES_ROOT\\Directory\\Background\\shell\\pc_easy"
        };

        if (enabled) {
            // 添加右键菜单项
            for (const QString &key : keys) {
                QSettings settings(key, QSettings::NativeFormat);
                settings.setValue(".", "使用pc_easy打开");
                settings.setValue("Icon", appPath);

                QSettings commandSettings(key + "\\command", QSettings::NativeFormat);
                commandSettings.setValue(".", "\"" + expPath + "\" \"%1\"");
            }
        } else {
            // 移除右键菜单项
            for (const QString &key : keys) {
                QSettings settings(key, QSettings::NativeFormat);
                settings.remove("");
            }
        }
    }

    SwitchButton *m_autoStartSwitch;
    SwitchButton *m_explorerShortcutSwitch;
    SwitchButton *m_powerrunShortcutSwitch;
    SwitchButton *m_contextMenuSwitch;
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

// 修改MainWindow类
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(bool autoRun = false, QWidget* parent = nullptr)
        : QMainWindow(parent), m_autoRun(autoRun) {
        setupUI();
        setupConnections();
        m_trayIcon->show();
        // 如果是自启动模式，最小化到托盘
        if (m_autoRun) {
            hide();

        }
    }

    void activateWindow() {
        HWND hwnd = (HWND)winId();
        qDebug() << hwnd;
        if (hwnd) {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            qDebug() << hwnd;
        }
    }

    ~MainWindow() {
        KeyboardHook::instance()->unregisterAll();
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

        // 添加退出按钮
        QPushButton* exitBtn = new QPushButton("退出程序");
        exitBtn->setFixedSize(100, 30);
        connect(exitBtn, &QPushButton::clicked, this, &MainWindow::exitApplication);

        buttonLayout->addStretch();
        buttonLayout->addWidget(aboutBtn);
        buttonLayout->addWidget(disclaimerBtn);
        buttonLayout->addWidget(settingsBtn);
        buttonLayout->addWidget(exitBtn); // 添加退出按钮
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
        connect(m_trayIcon, &TrayIcon::openScreenManagerRequested, this, [this]() { // 新增
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/screen_ok.exe");
        });
        connect(m_trayIcon, &TrayIcon::openAutorunRequested, this, [this]() {
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/AutorunManager.exe");
        });
        connect(m_trayIcon, &TrayIcon::openOptimizerRequested, this, [this]() {
            QProcess::startDetached(QCoreApplication::applicationDirPath() + "/SysOptimizer.exe");
        });
        connect(m_trayIcon, &TrayIcon::exitRequested, this, &MainWindow::exitApplication);

        // 连接快捷键信号
        connect(KeyboardHook::instance(), &KeyboardHook::shortcutTriggered, this, [this](const QString& id) {
            if (id == "explorer") {
                QProcess::startDetached(QCoreApplication::applicationDirPath() + "/Exp.exe");
            } else if (id == "powerrun") {
                QProcess::startDetached(QCoreApplication::applicationDirPath() + "/PowerRun.exe");
            }
        });
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
            "六层级权限控制系统，从沙盒到系统内核的完整权限管理。支持受限用户、普通用户、管理员、SYSTEM、TrustedInstaller和上帝模式。",
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

    // 添加退出处理函数
    void exitApplication() {
        // 确认退出
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "确认退出",
                                      "确定要退出 pc_easy 吗？",
                                      QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            // 清理资源
            KeyboardHook::instance()->unregisterAll();
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

            // // 显示提示消息
            // m_trayIcon->showMessage("pc_easy",
            //                         "程序已最小化到系统托盘\n右键点击托盘图标可退出程序",
            //                         QSystemTrayIcon::Information, 2000);
        } else {
            // 如果托盘不可用，直接退出
            QMainWindow::closeEvent(event);
        }
    }

    void showAboutDialog() {
        QMessageBox::about(this, "关于 pc_easy",
                           "<h2>pc_easy v2.3</h2>"
                           "<p><b>多功能系统工具集合</b></p>"
                           "<p>本工具集成了五个实用的系统工具：</p>"
                           "<ul>"
                           "<li><b>高级文件资源管理器</b> - 强大的文件管理和解锁工具</li>"
                           "<li><b>系统自启动管理器</b> - 全面的启动项管理</li>"
                           "<li><b>多权限运行工具</b> - 多种权限级别运行程序</li>"
                           "<li><b>高级窗口管理器</b> - 专业的窗口管理</li>"
                           "<li><b>一站式系统优化器</b> - 系统优化和安全设置</li>"
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
            "<p><b>六层级权限控制系统，从沙盒到系统内核的完整权限管理</b></p>"
            "<hr>"
            "<h4>六层级权限架构：</h4>"
            "<ul>"
            "<li><b>Level 1</b> - 受限用户（沙盒环境）</li>"
            "<li><b>Level 2</b> - 普通用户（标准UAC）</li>"
            "<li><b>Level 3</b> - 管理员权限</li>"
            "<li><b>Level 4</b> - SYSTEM系统权限</li>"
            "<li><b>Level 5</b> - TrustedInstaller权限</li>"
            "<li><b>Level 6</b> - 上帝模式（最高完整性令牌）</li>"
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

    // 设置应用程序唯一标识
    const QString appId = "pc_easy_instance";

    // 单实例检查（除非强制新实例）
    QSharedMemory sharedMemory;
    sharedMemory.setKey(appId);

    if (!forceNewInstance && sharedMemory.attach()) {
        QMessageBox::information(QWidget::createWindowContainer(QWindow::fromWinId((WId)GetDesktopWindow())), "提示", "pc_easy已经在运行，你可以在系统托盘中找到他。");
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

    // 检查注册表判断是否需要显示免责声明
    QSettings settings("HKEY_CURRENT_USER\\Software\\pc_easy", QSettings::NativeFormat);
    bool disclaimerAgreed = settings.value("disclaimerHasBeenAgreed", false).toBool();

    if (!disclaimerAgreed) {
        DisclaimerDialog dlg;
        if (dlg.exec() == QDialog::Accepted) {
            // 用户同意后设置注册表值
            settings.setValue("disclaimerHasBeenAgreed", true);
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
