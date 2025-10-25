#include <Windows.h>
#include <QtWidgets>
#include <tlhelp32.h>
#include <QString>
#include <QTableWidget>
#include <QThread>
#include <tchar.h>
#include <psapi.h>
#include <shellapi.h>
#include <QFile>
#include <QApplication>
#include <QtConcurrent/QtConcurrent>
#include <QMessageBox>
#include <QTabWidget>
#include <QHeaderView>
#include <QElapsedTimer>
#include <QTimer>
#include <QInputDialog>
#include <QSlider>
#include <QDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QProgressDialog>

// 窗口设置结构体
struct WindowSettings {
    QString title;
    bool hascaption;
    int width;
    int height;
    int opacity;
    bool hasSysMenu;
    bool sizable;
    bool minimizeBox;
    bool maximizeBox;
    bool alwaysOnTop;
    bool toolWindow;
    bool noActivate;
    DWORD processPriority;
};

// 获取窗口图标
QIcon GetWindowIcon(HWND hwnd) {
    HICON hIcon = (HICON)SendMessage(hwnd, WM_GETICON, ICON_SMALL2, 0);
    if (!hIcon) hIcon = (HICON)SendMessage(hwnd, WM_GETICON, ICON_SMALL, 0);
    if (!hIcon) hIcon = (HICON)SendMessage(hwnd, WM_GETICON, ICON_BIG, 0);
    if (!hIcon) hIcon = (HICON)GetClassLongPtr(hwnd, GCLP_HICONSM);
    if (!hIcon) hIcon = (HICON)GetClassLongPtr(hwnd, GCLP_HICON);

    if (hIcon) {
        return QIcon(QPixmap::fromImage(QImage::fromHICON(hIcon)));
    }
    return QApplication::windowIcon();
}

// 获取进程名称
QString GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        WCHAR filename[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, filename, MAX_PATH)) {
            CloseHandle(hProcess);
            QFileInfo fileInfo(QString::fromWCharArray(filename));
            return fileInfo.fileName();
        }
        CloseHandle(hProcess);
    }
    return "Unknown";
}

// 应用窗口设置
void ApplyWindowSettings(HWND hwnd, const WindowSettings &settings) {
    if (!IsWindow(hwnd)) return; // 安全性检查

    // 应用窗口标题
    if (!settings.title.isEmpty()) {
        SetWindowTextW(hwnd, reinterpret_cast<LPCWSTR>(settings.title.utf16()));
    }

    // 应用窗口大小
    if (settings.width > 0 && settings.height > 0) {
        SetWindowPos(hwnd, NULL, 0, 0, settings.width, settings.height,
                     SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }

    // 应用窗口样式
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    style &= ~(WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);

    if (settings.hascaption) style |= WS_CAPTION;
    if (settings.hasSysMenu) style |= WS_SYSMENU;
    if (settings.sizable) style |= WS_THICKFRAME;
    if (settings.minimizeBox) style |= WS_MINIMIZEBOX;
    if (settings.maximizeBox) style |= WS_MAXIMIZEBOX;

    SetWindowLongPtr(hwnd, GWL_STYLE, style);

    // 获取当前扩展样式
    LONG_PTR currentExStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    bool isLayered = (currentExStyle & WS_EX_LAYERED) != 0;
    bool needSetLayered = false;
    BYTE opacityToSet = settings.opacity;

    // 检查是否需要添加分层属性
    if (!isLayered && settings.opacity < 255) {
        // 弹出提示框询问用户
        int ret = QMessageBox::question(
            nullptr,
            "分层窗口警告",
            "该窗口当前不支持透明度效果。强制添加分层属性可能导致渲染异常或功能异常。\n是否继续操作？",
            QMessageBox::Yes | QMessageBox::No
            );

        if (ret == QMessageBox::Yes) {
            needSetLayered = true;  // 用户确认继续
        }
    }

    // 构建新的扩展样式
    LONG_PTR exStyle = currentExStyle;
    exStyle &= ~(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE);

    // 应用用户设置的样式
    if (settings.alwaysOnTop) exStyle |= WS_EX_TOPMOST;
    if (settings.toolWindow) exStyle |= WS_EX_TOOLWINDOW;
    if (settings.noActivate) exStyle |= WS_EX_NOACTIVATE;

    // 按需添加分层属性
    if (needSetLayered) exStyle |= WS_EX_LAYERED;

    // 设置新的扩展样式
    SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle);

    // 应用透明度设置（仅当窗口支持分层属性时）
    if (exStyle & WS_EX_LAYERED) {
        SetLayeredWindowAttributes(hwnd, 0, opacityToSet, LWA_ALPHA);
    }

    // 应用窗口优先级
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, processId);
    if (hProcess) {
        SetPriorityClass(hProcess, settings.processPriority);
        CloseHandle(hProcess);
    }

    // 应用置顶设置（单独处理，因为SetWindowPos的Z序参数更可靠）
    if (settings.alwaysOnTop) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    } else {
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

// 主窗口类
class WindowManager : public QWidget {
    Q_OBJECT

private:
    struct WindowData {
        HWND hwnd;
        QString title;
        DWORD processId;
    };

public:
    WindowManager(QWidget *parent = nullptr) : QWidget(parent), progressDialog(nullptr) {
        qDebug() << "开始创建WindowManager对象";

        setWindowTitle("窗口管理器");
        qDebug() << "设置窗口标题完成";

        setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
        qDebug() << "设置窗口标志完成";

        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        qDebug() << "创建主布局完成";

        // 创建表格
        table = new QTableWidget();
        qDebug() << "创建表格对象完成";

        table->setColumnCount(3);
        QStringList headers{"图标", "窗口标题", "所属进程"};
        table->setHorizontalHeaderLabels(headers);
        qDebug() << "设置表格列和标题完成";

        // 设置表格属性
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        table->verticalHeader()->setDefaultSectionSize(28);
        table->setIconSize(QSize(20, 20));
        qDebug() << "设置表格属性完成";

        // 按钮布局
        QPushButton *refreshButton = new QPushButton("刷新窗口列表");
        QPushButton *findButton = new QPushButton("查找窗口");
        qDebug() << "创建按钮完成";

        QHBoxLayout *buttonLayout = new QHBoxLayout();
        buttonLayout->addWidget(refreshButton);
        buttonLayout->addWidget(findButton);
        qDebug() << "创建按钮布局完成";

        // 连接信号槽
        connect(refreshButton, &QPushButton::clicked, this, &WindowManager::PopulateWindowTable);
        connect(findButton, &QPushButton::clicked, this, &WindowManager::FindWindow);
        connect(table, &QTableWidget::customContextMenuRequested, this, &WindowManager::ShowContextMenu);
        qDebug() << "连接信号槽完成";

        // 布局
        mainLayout->addWidget(table);
        mainLayout->addLayout(buttonLayout);
        qDebug() << "添加控件到布局完成";

        setMinimumSize(400, 300);
        qDebug() << "设置最小尺寸完成";

        // 设置键盘钩子
        hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
        if (hKeyboardHook) {
            qDebug() << "键盘钩子设置成功";
        } else {
            DWORD error = GetLastError();
            qDebug() << "键盘钩子设置失败，错误代码:" << error;
        }

        // 填充表格
        PopulateWindowTable();
        qDebug() << "填充表格数据完成";

        qDebug() << "WindowManager构造函数完成";
    }

    ~WindowManager() {
        // 清理钩子
        if (hKeyboardHook) {
            UnhookWindowsHookEx(hKeyboardHook);
            qDebug() << "键盘钩子已卸载";
        }

        // 清理进度对话框
        if (progressDialog) {
            delete progressDialog;
        }
    }

private slots:
    void PopulateWindowTable() {
        qDebug() << "开始填充表格数据";

        // 创建进度对话框
        if (!progressDialog) {
            progressDialog = new QProgressDialog("正在收集窗口信息...", "取消", 0, 0, this);
            progressDialog->setWindowModality(Qt::WindowModal);
            progressDialog->setCancelButton(nullptr); // 暂时禁用取消按钮
            progressDialog->setMinimumDuration(0);
        }
        progressDialog->show();

        table->clearContents();
        table->setRowCount(0);

        // 收集窗口数据（在非UI线程）
        QtConcurrent::run([this]() {
            qDebug() << "在后台线程开始枚举窗口";
            QVector<WindowData> windowList;

            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                QVector<WindowData>* list = reinterpret_cast<QVector<WindowData>*>(lParam);

                if (IsWindowVisible(hwnd)) {
                    WCHAR title[256];
                    if (GetWindowText(hwnd, title, 256) > 0) {
                        QString windowTitle = QString::fromWCharArray(title);
                        if (!windowTitle.isEmpty()) {
                            DWORD processId;
                            GetWindowThreadProcessId(hwnd, &processId);

                            WindowData data;
                            data.hwnd = hwnd;
                            data.title = windowTitle;
                            data.processId = processId;
                            list->append(data);
                        }
                    }
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&windowList));

            qDebug() << "枚举窗口完成，找到" << windowList.size() << "个窗口";

            // 在主线程更新UI
            QMetaObject::invokeMethod(this, [this, windowList]() {
                qDebug() << "在主线程更新表格";

                // 关闭进度对话框
                if (progressDialog) {
                    progressDialog->close();
                }

                table->setRowCount(windowList.size());

                for (int i = 0; i < windowList.size(); ++i) {
                    const WindowData& data = windowList[i];

                    // 第一列：图标
                    QTableWidgetItem *iconItem = new QTableWidgetItem();
                    iconItem->setIcon(GetWindowIcon(data.hwnd));
                    table->setItem(i, 0, iconItem);

                    // 第二列：标题
                    QTableWidgetItem *titleItem = new QTableWidgetItem(data.title);
                    table->setItem(i, 1, titleItem);

                    // 第三列：进程
                    QTableWidgetItem *processItem = new QTableWidgetItem(GetProcessName(data.processId));
                    table->setItem(i, 2, processItem);

                    // 存储窗口句柄
                    titleItem->setData(Qt::UserRole, reinterpret_cast<qulonglong>(data.hwnd));
                }
                qDebug() << "表格更新完成";
            });
        });
    }

    void FindWindow() {
        QMessageBox::information(this, "提示", "请在3秒内将鼠标移动到目标窗口上");
        Sleep(3000);
        POINT pt;
        GetCursorPos(&pt);
        HWND hwnd = WindowFromPoint(pt);

        if (hwnd && IsWindowVisible(hwnd)) {
            // 在表格中查找窗口
            int row = -1;
            for (int i = 0; i < table->rowCount(); ++i) {
                QTableWidgetItem *item = table->item(i, 1);
                if (item) {
                    HWND itemHwnd = reinterpret_cast<HWND>(item->data(Qt::UserRole).toULongLong());
                    if (itemHwnd == hwnd) {
                        row = i;
                        break;
                    }
                }
            }

            if (row == -1) {
                // 添加新窗口
                WCHAR title[256];
                if (GetWindowText(hwnd, title, 256) > 0) {
                    QString windowTitle = QString::fromWCharArray(title);
                    if (!windowTitle.isEmpty()) {
                        DWORD processId;
                        GetWindowThreadProcessId(hwnd, &processId);

                        int newRow = table->rowCount();
                        table->insertRow(newRow);

                        // 添加数据
                        QTableWidgetItem *iconItem = new QTableWidgetItem();
                        iconItem->setIcon(GetWindowIcon(hwnd));
                        table->setItem(newRow, 0, iconItem);

                        QTableWidgetItem *titleItem = new QTableWidgetItem(windowTitle);
                        table->setItem(newRow, 1, titleItem);

                        QTableWidgetItem *processItem = new QTableWidgetItem(GetProcessName(processId));
                        table->setItem(newRow, 2, processItem);

                        titleItem->setData(Qt::UserRole, reinterpret_cast<qulonglong>(hwnd));
                        row = newRow;
                    }
                }
            }

            // 选中并滚动到该行
            if (row >= 0) {
                table->selectRow(row);
                table->scrollToItem(table->item(row, 0));
            }
        }
    }

    void ShowContextMenu(const QPoint &pos) {
        QTableWidgetItem *item = table->itemAt(pos);
        if (!item) {
            // 空白区域处理
            QMenu menu;
            menu.addAction("刷新列表", this, &WindowManager::PopulateWindowTable);
            menu.addAction("关于", []() {
                QMessageBox::about(nullptr, "窗口管理器",
                                   "高级窗口管理工具\n"
                                   "版本 2.3\n"
                                   "使用说明：\n"
                                   "1. 左键选择窗口\n"
                                   "2. 右键显示菜单\n"
                                   "3. 使用查找功能添加新窗口");
            });
            menu.exec(table->viewport()->mapToGlobal(pos));
            return;
        }

        HWND hwnd = reinterpret_cast<HWND>(item->data(Qt::UserRole).toULongLong());
        if (!IsWindow(hwnd)) return;

        // 获取窗口属性
        WindowSettings settings;

        // 标题
        WCHAR title[256];
        if (GetWindowText(hwnd, title, 256) > 0) {
            settings.title = QString::fromWCharArray(title);
        } else {
            settings.title = "<空标题>";
        }

        // 尺寸
        RECT rect;
        if (GetWindowRect(hwnd, &rect)) {
            settings.width = rect.right - rect.left;
            settings.height = rect.bottom - rect.top;
        } else {
            settings.width = 0;
            settings.height = 0;
        }

        // 样式
        LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
        if (style != 0) {
            settings.hascaption = (style & WS_CAPTION) != 0;
            settings.hasSysMenu = (style & WS_SYSMENU) != 0;
            settings.sizable = (style & WS_THICKFRAME) != 0;
            settings.minimizeBox = (style & WS_MINIMIZEBOX) != 0;
            settings.maximizeBox = (style & WS_MAXIMIZEBOX) != 0;
        }

        // 扩展样式
        LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
        if (exStyle != 0) {
            settings.alwaysOnTop = (exStyle & WS_EX_TOPMOST) != 0;
            settings.toolWindow = (exStyle & WS_EX_TOOLWINDOW) != 0;
            settings.noActivate = (exStyle & WS_EX_NOACTIVATE) != 0;
        }

        // 透明度
        BYTE alpha;
        if (GetLayeredWindowAttributes(hwnd, NULL, &alpha, NULL)) {
            settings.opacity = alpha;
        } else {
            settings.opacity = 255;
        }

        // 进程优先级
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess) {
            settings.processPriority = GetPriorityClass(hProcess);
            CloseHandle(hProcess);
        } else {
            settings.processPriority = NORMAL_PRIORITY_CLASS;
        }

        // 创建菜单
        QMenu menu;
        QAction *selectedAction = nullptr;

        // === 基础操作 ===
        QAction *moveAction = menu.addAction("移动窗口");
        // QAction *templateAction = menu.addAction("窗口模板");
        // 尺寸设置
        QMenu *sizeMenu = menu.addMenu(QString("设置大小 (%1×%2)").arg(settings.width).arg(settings.height));
        QAction *widthAction = sizeMenu->addAction("设置宽度");
        QAction *heightAction = sizeMenu->addAction("设置高度");
        menu.addSeparator();

        // === 窗口操作 ===
        QAction *hideAction = menu.addAction("隐藏窗口");
        QAction *showAction = menu.addAction("显示窗口");
        QAction *minimizeAction = menu.addAction("最小化");
        QAction *maximizeAction = menu.addAction("最大化");
        QAction *restoreAction = menu.addAction("还原");
        QAction *fullscreenAction = menu.addAction("全屏");
        menu.addSeparator();

        // === 属性设置菜单 ===
        QMenu *settingsMenu = menu.addMenu("属性设置");

        // 标题设置
        QAction *titleAction = settingsMenu->addAction(QString("设置标题 (%1)").arg(settings.title));

        // 样式设置
        QMenu *styleMenu = settingsMenu->addMenu("样式设置");
        QAction *captionAction = styleMenu->addAction("标题栏");
        captionAction->setCheckable(true);
        captionAction->setChecked(settings.hascaption);

        QAction *sysMenuAction = styleMenu->addAction("系统菜单");
        sysMenuAction->setCheckable(true);
        sysMenuAction->setChecked(settings.hasSysMenu);

        QAction *sizableAction = styleMenu->addAction("可调整大小");
        sizableAction->setCheckable(true);
        sizableAction->setChecked(settings.sizable);

        QAction *minimizeBoxAction = styleMenu->addAction("最小化按钮");
        minimizeBoxAction->setCheckable(true);
        minimizeBoxAction->setChecked(settings.minimizeBox);

        QAction *maximizeBoxAction = styleMenu->addAction("最大化按钮");
        maximizeBoxAction->setCheckable(true);
        maximizeBoxAction->setChecked(settings.maximizeBox);

        // 高级设置
        QMenu *advancedMenu = settingsMenu->addMenu("高级设置");

        // 透明度
        QAction *opacityAction = advancedMenu->addAction(QString("设置透明度 (%1)").arg(settings.opacity));

        // 窗口样式
        QAction *topMostAction = advancedMenu->addAction("窗口置顶");
        topMostAction->setCheckable(true);
        topMostAction->setChecked(settings.alwaysOnTop);

        QAction *toolWindowAction = advancedMenu->addAction("工具窗口");
        toolWindowAction->setCheckable(true);
        toolWindowAction->setChecked(settings.toolWindow);

        QAction *noActivateAction = advancedMenu->addAction("不激活窗口");
        noActivateAction->setCheckable(true);
        noActivateAction->setChecked(settings.noActivate);

        // 优先级设置
        QMenu *priorityMenu = settingsMenu->addMenu("设置优先级");
        QActionGroup priorityGroup(&menu); // 父对象绑定
        priorityGroup.setExclusive(true);

        auto addPriorityAction = [&](const QString &text, DWORD value) {
            QAction *action = new QAction(text, priorityMenu);
            action->setCheckable(true);
            action->setChecked(settings.processPriority == value);
            priorityGroup.addAction(action);
            priorityMenu->addAction(action);
            action->setData(static_cast<uint>(value));
        };

        addPriorityAction("实时", REALTIME_PRIORITY_CLASS);
        addPriorityAction("高", HIGH_PRIORITY_CLASS);
        addPriorityAction("高于正常", ABOVE_NORMAL_PRIORITY_CLASS);
        addPriorityAction("正常", NORMAL_PRIORITY_CLASS);
        addPriorityAction("低于正常", BELOW_NORMAL_PRIORITY_CLASS);
        addPriorityAction("空闲", IDLE_PRIORITY_CLASS);

        menu.addSeparator();
        QAction *closeAction = menu.addAction("关闭");
        QAction *forceCloseAction = menu.addAction("强制关闭");

        // 显示菜单
        selectedAction = menu.exec(table->viewport()->mapToGlobal(pos));

        // 处理用户操作
        if (selectedAction) {
            // 样式设置
            if (selectedAction == captionAction) {
                settings.hascaption = captionAction->isChecked();
            } else if (selectedAction == sysMenuAction) {
                settings.hasSysMenu = sysMenuAction->isChecked();
            } else if (selectedAction == sizableAction) {
                settings.sizable = sizableAction->isChecked();
            } else if (selectedAction == minimizeBoxAction) {
                settings.minimizeBox = minimizeBoxAction->isChecked();
            } else if (selectedAction == maximizeBoxAction) {
                settings.maximizeBox = maximizeBoxAction->isChecked();
            } else if (selectedAction == topMostAction) {
                settings.alwaysOnTop = topMostAction->isChecked();
            } else if (selectedAction == toolWindowAction) {
                settings.toolWindow = toolWindowAction->isChecked();
            } else if (selectedAction == noActivateAction) {
                settings.noActivate = noActivateAction->isChecked();
            }
            // 标题设置
            else if (selectedAction == titleAction) {
                bool ok;
                QString newTitle = QInputDialog::getText(this, "设置窗口标题", "新标题:",
                                                         QLineEdit::Normal, settings.title, &ok);
                if (ok && !newTitle.isEmpty()) {
                    settings.title = newTitle;
                }
            }
            // 宽度设置
            else if (selectedAction == widthAction) {
                bool ok;
                int newWidth = QInputDialog::getInt(this, "设置窗口宽度", "宽度:",
                                                    settings.width, 100, 10000, 10, &ok);
                if (ok) settings.width = newWidth;
            }
            // 高度设置
            else if (selectedAction == heightAction) {
                bool ok;
                int newHeight = QInputDialog::getInt(this, "设置窗口高度", "高度:",
                                                     settings.height, 100, 10000, 10, &ok);
                if (ok) settings.height = newHeight;
            }
            // 透明度设置
            else if (selectedAction == opacityAction) {
                QDialog dialog(this);
                dialog.setWindowTitle("设置透明度");
                QVBoxLayout layout(&dialog);

                QLabel label(QString("当前透明度: %1").arg(settings.opacity));
                QSlider slider(Qt::Horizontal);
                slider.setRange(0, 255);
                slider.setValue(settings.opacity);

                QObject::connect(&slider, &QSlider::valueChanged, [&](int value){
                    label.setText(QString("当前透明度: %1").arg(value));
                    settings.opacity = value;
                    // 实时更新透明度
                    ApplyWindowSettings(hwnd, settings);
                });

                layout.addWidget(&label);
                layout.addWidget(&slider);
                dialog.exec();
            }
            // 优先级设置
            else if (priorityGroup.actions().contains(selectedAction)) {
                settings.processPriority = selectedAction->data().toUInt();
            }

            // 应用设置（透明度已在对话框中应用）
            if (selectedAction != opacityAction) {
                ApplyWindowSettings(hwnd, settings);
            }

            // 特殊操作
            if (selectedAction == moveAction) {
                QMessageBox::information(this, "提示", "请在3秒内将鼠标移动到位置上，随后指定窗口会移动到指定位置");
                Sleep(3000);
                POINT pt;
                GetCursorPos(&pt);
                SetWindowPos(hwnd, NULL,
                             pt.x,
                             pt.y,
                             0, 0,
                             SWP_NOSIZE | SWP_NOZORDER);
            }
            else if (selectedAction == hideAction) {
                ShowWindow(hwnd, SW_HIDE);
            }
            else if (selectedAction == showAction) {
                ShowWindow(hwnd, SW_SHOW);
                SetForegroundWindow(hwnd);
            }
            else if (selectedAction == minimizeAction) {
                ShowWindow(hwnd, SW_MINIMIZE);
            }
            else if (selectedAction == maximizeAction) {
                ShowWindow(hwnd, SW_MAXIMIZE);
            }
            else if (selectedAction == restoreAction) {
                ShowWindow(hwnd, SW_RESTORE);
            }
            else if (selectedAction == fullscreenAction) {
                // 全屏功能
                LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
                if (style & WS_OVERLAPPEDWINDOW) {
                    MONITORINFO monitorInfo = { sizeof(monitorInfo) };
                    if (GetMonitorInfo(MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY), &monitorInfo)) {
                        SetWindowLongPtr(hwnd, GWL_STYLE, style & ~WS_OVERLAPPEDWINDOW);
                        SetWindowPos(hwnd, HWND_TOP,
                                     monitorInfo.rcMonitor.left,
                                     monitorInfo.rcMonitor.top,
                                     monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left,
                                     monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top,
                                     SWP_FRAMECHANGED);
                    }
                } else {
                    // 恢复窗口
                    SetWindowLongPtr(hwnd, GWL_STYLE, style | WS_OVERLAPPEDWINDOW);
                    ShowWindow(hwnd, SW_RESTORE);
                }
            }
            else if (selectedAction == closeAction) {
                PostMessage(hwnd, WM_CLOSE, 0, 0);
            }
            else if (selectedAction == forceCloseAction) {
                DWORD processId;
                GetWindowThreadProcessId(hwnd, &processId);
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }

            // 刷新窗口
            SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED | SWP_NOACTIVATE);
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
        }
    }

private:
    QTableWidget *table;
    HHOOK hKeyboardHook;
    QProgressDialog *progressDialog;

    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
        static bool winPressed = false;
        static bool altPressed = false;

        if (nCode == HC_ACTION) {
            PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;

            // 更新Win键状态
            if (p->vkCode == VK_LWIN || p->vkCode == VK_RWIN) {
                if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                    winPressed = true;
                } else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
                    winPressed = false;
                }
            }

            // 更新Alt键状态（使用数值替代常量）
            if (p->vkCode == 0xA4 || p->vkCode == 0xA5) { // VK_LALT 和 VK_RALT
                if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                    altPressed = true;
                } else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
                    altPressed = false;
                }
            }

            // 检测组合键
            if (winPressed && altPressed) {
                // 拦截所有组合键事件，防止触发系统行为
                if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                    // 检查是否是功能键
                    if (p->vkCode == 'H' || p->vkCode == 'N' || p->vkCode == 'M' ||
                        p->vkCode == 'R' || p->vkCode == 'C' || p->vkCode == 'F') {
                        // 处理功能键
                        HWND hwnd = GetForegroundWindow();
                        if (IsWindow(hwnd)) {
                            switch (p->vkCode) {
                            case 'H':
                                ShowWindow(hwnd, SW_HIDE);
                                break;
                            case 'N':
                                ShowWindow(hwnd, SW_MINIMIZE);
                                break;
                            case 'M':
                                ShowWindow(hwnd, SW_MAXIMIZE);
                                break;
                            case 'R':
                                ShowWindow(hwnd, SW_RESTORE);
                                break;
                            case 'C':
                                PostMessage(hwnd, WM_CLOSE, 0, 0);
                                break;
                            case 'F':
                            {
                                LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
                                if (style & WS_OVERLAPPEDWINDOW) {
                                    MONITORINFO monitorInfo = { sizeof(monitorInfo) };
                                    HMONITOR hMonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
                                    if (GetMonitorInfo(hMonitor, &monitorInfo)) {
                                        SetWindowLongPtr(hwnd, GWL_STYLE, style & ~WS_OVERLAPPEDWINDOW);
                                        SetWindowPos(hwnd, HWND_TOP,
                                                     monitorInfo.rcMonitor.left,
                                                     monitorInfo.rcMonitor.top,
                                                     monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left,
                                                     monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top,
                                                     SWP_FRAMECHANGED);
                                    }
                                } else {
                                    SetWindowLongPtr(hwnd, GWL_STYLE, style | WS_OVERLAPPEDWINDOW);
                                    ShowWindow(hwnd, SW_RESTORE);
                                }
                                break;
                            }
                            }
                        }
                    }
                    // 拦截所有组合键事件（包括Win和Alt键本身）
                    return 1; // 阻止事件传播
                }
            }
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }
};

// 全局变量用于存储应用程序实例
WindowManager* g_windowManager = nullptr;

int main(int argc, char *argv[]) {
    qDebug() << "应用程序开始";
    QApplication app(argc, argv);
    qDebug() << "QApplication对象创建完成";

    // 抑制系统错误对话框
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    qDebug() << "设置错误模式完成";

    WindowManager windowManager;
    g_windowManager = &windowManager; // 设置全局实例
    qDebug() << "WindowManager对象创建完成";

    windowManager.show();
    qDebug() << "调用show()方法";

    windowManager.raise();
    qDebug() << "调用raise()方法";

    windowManager.activateWindow();
    qDebug() << "调用activateWindow()方法";

    qDebug() << "进入事件循环";
    int result = app.exec();
    qDebug() << "事件循环结束，返回值:" << result;

    g_windowManager = nullptr; // 清除全局实例
    return result;
}

#include "main.moc"
