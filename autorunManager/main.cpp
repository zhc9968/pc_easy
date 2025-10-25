#include "DigitalSignatureVerifier.h"
#include <QtWidgets>
#include <Windows.h>
#include <winreg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <QThread>
#include <QFuture>
#include <QtConcurrent/QtConcurrent>
#include <wintrust.h>
#include <softpub.h>
#include <cryptuiapi.h>
#include <QMessageBox>
#include <QProgressDialog>
#include <QFileDialog>
#include <QMenu>
#include <QClipboard>
#include <QProcess>
#include <QDir>
#include <QFileInfo>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QCheckBox>
#include <QHeaderView>
#include <QLabel>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QApplication>
#include <QFutureWatcher>
#include <QMap>
#include <QVector>
#include <QList>
#include <QString>
#include <functional>
#include <memory>
#include <QtWidgets>
#include <Windows.h>
#include <winreg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <QThread>
#include <QFuture>
#include <QtConcurrent/QtConcurrent>
#include <wintrust.h>
#include <softpub.h>
#include <cryptuiapi.h>
#include <mscat.h>  // 添加目录签名相关的头文件

const IID IID_IPersistFile = {0x0000010b, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
const IID IID_IShellLinkW = {0x000214F9, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

class StartupManager : public QMainWindow {
    Q_OBJECT

public:
    StartupManager(QWidget *parent = nullptr) : QMainWindow(parent) {
        setupUI();
        loadAllStartupsAsync();
    }

private slots:
    void showFileInfo(QTreeWidgetItem *item, int column) {
        if (!item || item->childCount() > 0) return;

        QString filePath = item->text(2);
        if (filePath.isEmpty()) return;

        filePath = expandEnvironmentVariables(filePath);
        QString fileInfo = getFileInfo(filePath);

        // 获取详细的签名信息
        QString signatureDetails = signatureVerifier.getSignatureDetails(filePath);

        QMessageBox::information(this, "文件信息",
                                 QString("文件路径: %1\n\n文件信息:\n%2\n\n数字签名详细信息:\n%3")
                                     .arg(filePath)
                                     .arg(fileInfo)
                                     .arg(signatureDetails));
    }

    void onDeleteItem(QTreeWidget *tree, QTreeWidgetItem *item) {
        if (!tree || !item) return;

        if (item->childCount() > 0) {
            QMessageBox::warning(this, "错误", "不能删除分类节点");
            return;
        }

        QString name = item->text(1);
        QString location = item->data(0, Qt::UserRole).toString();

        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "确认删除",
                                      QString("确定要删除启动项 '%1' 吗?").arg(name),
                                      QMessageBox::Yes|QMessageBox::No);
        if (reply != QMessageBox::Yes) return;

        // 处理启动文件夹删除
        if (tree == startupFoldersTree) {
            QString filePath = item->data(0, Qt::UserRole).toString();
            if (filePath.isEmpty()) return;

            if (QFile::remove(filePath)) {
                QTreeWidgetItem *parent = item->parent();
                if (parent) {
                    parent->removeChild(item);
                    delete item;

                    if (parent->childCount() == 0) {
                        QTreeWidgetItem *grandParent = parent->parent();
                        if (grandParent) {
                            grandParent->removeChild(parent);
                            delete parent;
                        }
                    }
                }
                QMessageBox::information(this, "成功", "启动项已成功删除");
                refreshAll();
            } else {
                showDetailedError("删除文件", filePath, GetLastError());
            }
            return;
        }

        QStringList parts = location.split("\\");
        if (parts.size() < 2) return;

        HKEY hive = NULL;
        if (parts[0] == "HKEY_LOCAL_MACHINE") hive = HKEY_LOCAL_MACHINE;
        else if (parts[0] == "HKEY_CURRENT_USER") hive = HKEY_CURRENT_USER;
        else return;

        QString subKey = parts.mid(1).join("\\");
        QString valueName = name;

        HKEY hKey;
        LONG result = RegOpenKeyExA(hive, subKey.toStdString().c_str(), 0, KEY_WRITE, &hKey);
        if (result == ERROR_SUCCESS) {
            result = RegDeleteValueA(hKey, valueName.toStdString().c_str());
            if (result == ERROR_SUCCESS) {
                QTreeWidgetItem *parent = item->parent();
                if (parent) {
                    parent->removeChild(item);
                    delete item;

                    if (parent->childCount() == 0) {
                        QTreeWidgetItem *grandParent = parent->parent();
                        if (grandParent) {
                            grandParent->removeChild(parent);
                            delete parent;
                        }
                    }
                }
                QMessageBox::information(this, "成功", "启动项已成功删除");
                refreshAll(); // 删除成功后刷新
            } else {
                showDetailedError("删除注册表值", location, result);
            }
            RegCloseKey(hKey);
        } else {
            showDetailedError("打开注册表键", location, result);
        }
    }

    void onEditItem(QTreeWidget *tree, QTreeWidgetItem *item) {
        if (!tree || !item || item->childCount() > 0) return;

        if (tree == winlogonTree) {
            editWinlogonItemDialog(item);
            return;
        }

        if (tree == startupFoldersTree) {
            editStartupFolderItemDialog(item);
            return;
        }

        QString name = item->text(1);
        QString filePath = item->text(2);
        QString location = item->data(0, Qt::UserRole).toString();

        QDialog dialog(this);
        dialog.setWindowTitle("编辑启动项");
        QFormLayout layout(&dialog);

        QLineEdit nameEdit(&dialog);
        nameEdit.setText(name);
        layout.addRow("名称:", &nameEdit);

        QLineEdit pathEdit(&dialog);
        pathEdit.setText(filePath);
        layout.addRow("路径:", &pathEdit);

        QDialogButtonBox buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, &dialog);
        layout.addRow(&buttonBox);

        connect(&buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(&buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted) {
            QString newName = nameEdit.text().trimmed();
            QString newPath = pathEdit.text().trimmed();

            if (newName.isEmpty() || newPath.isEmpty()) {
                QMessageBox::warning(this, "错误", "名称和路径不能为空");
                return;
            }

            // 解析注册表位置
            QStringList parts = location.split("\\");
            if (parts.size() < 2) return;

            HKEY hive = NULL;
            if (parts[0] == "HKEY_LOCAL_MACHINE") hive = HKEY_LOCAL_MACHINE;
            else if (parts[0] == "HKEY_CURRENT_USER") hive = HKEY_CURRENT_USER;
            else return;

            QString subKey = parts.mid(1).join("\\");

            // 打开注册表键
            HKEY hKey;
            LONG result = RegOpenKeyExA(hive, subKey.toStdString().c_str(), 0, KEY_WRITE, &hKey);
            if (result == ERROR_SUCCESS) {
                if (newName != name) {
                    RegDeleteValueA(hKey, name.toStdString().c_str());
                }

                const char *valueData = newPath.toStdString().c_str();
                result = RegSetValueExA(hKey, newName.toStdString().c_str(), 0, REG_SZ,
                                        (const BYTE*)valueData, strlen(valueData) + 1);
                if (result == ERROR_SUCCESS) {
                    item->setText(1, newName);
                    item->setText(2, newPath);
                    item->setToolTip(2, newPath);

                    QString cleanPath = cleanFilePath(expandEnvironmentVariables(newPath));
                    QString description = getFileDescription(cleanPath);
                    item->setText(3, description);
                    item->setToolTip(3, description);

                    // 更新签名信息
                    QString signature = verifyDigitalSignature(cleanPath);
                    item->setText(5, signature);
                    item->setToolTip(5, signature);
                    updateSignatureColor(item, signature);

                    QMessageBox::information(this, "成功", "启动项已更新");
                    refreshAll(); // 编辑成功后刷新
                } else {
                    showDetailedError("更新注册表值", location, result);
                }
                RegCloseKey(hKey);
            } else {
                showDetailedError("打开注册表键", location, result);
            }
        }
    }

    void onAddItem(QTreeWidget *tree, QTreeWidgetItem *parentItem) {
        if (!tree) return;

        // 对于Winlogon树，使用特殊处理
        if (tree == winlogonTree) {
            addWinlogonItemDialog(parentItem);
            return;
        }

        // 对于启动文件夹树
        if (tree == startupFoldersTree) {
            addStartupFolderItemDialog(parentItem);
            return;
        }

        // 确定默认位置
        QString defaultLocation;
        QString defaultCategory;

        if (tree == systemRegistryTree) {
            defaultLocation = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            defaultCategory = "Run";
        } else if (tree == wow64RegistryTree) {
            defaultLocation = "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
            defaultCategory = "Run";
        } else if (tree == userRegistryTree) {
            defaultLocation = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            defaultCategory = "Run";
        }

        // 创建添加对话框
        QDialog dialog(this);
        dialog.setWindowTitle("添加启动项");
        QFormLayout layout(&dialog);

        QLineEdit nameEdit(&dialog);
        layout.addRow("名称:", &nameEdit);

        QLineEdit pathEdit(&dialog);
        QPushButton browseButton("浏览...", &dialog);
        QHBoxLayout pathLayout;
        pathLayout.addWidget(&pathEdit);
        pathLayout.addWidget(&browseButton);
        layout.addRow("路径:", &pathLayout);

        QComboBox locationCombo(&dialog);
        if (tree == systemRegistryTree) {
            locationCombo.addItems({
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad"
            });
        } else if (tree == wow64RegistryTree) {
            locationCombo.addItems({
                "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad"
            });
        } else if (tree == userRegistryTree) {
            locationCombo.addItems({
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                "HKEY_CURRENT_USER\\Environment\\UserInitMprLogonScript",
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad"
            });
        }
        locationCombo.setCurrentText(defaultLocation);
        layout.addRow("位置:", &locationCombo);

        // 添加位置说明
        QLabel *locationDescLabel = new QLabel(&dialog);
        QString locationDesc = registryLocationDescriptions.value(defaultLocation, "未知位置");
        locationDescLabel->setText("位置说明: " + locationDesc);
        layout.addRow(locationDescLabel);

        QDialogButtonBox buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, &dialog);
        layout.addRow(&buttonBox);

        connect(&browseButton, &QPushButton::clicked, [&]() {
            QString file = QFileDialog::getOpenFileName(this, "选择可执行文件", "", "可执行文件 (*.exe);;所有文件 (*.*)");
            if (!file.isEmpty()) {
                pathEdit.setText(file);
            }
        });

        connect(&buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(&buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted) {
            QString name = nameEdit.text().trimmed();
            QString path = pathEdit.text().trimmed();
            QString location = locationCombo.currentText();

            if (name.isEmpty() || path.isEmpty()) {
                QMessageBox::warning(this, "错误", "名称和路径不能为空");
                return;
            }

            // 解析注册表位置
            QStringList parts = location.split("\\");
            if (parts.size() < 2) return;

            HKEY hive = NULL;
            if (parts[0] == "HKEY_LOCAL_MACHINE") hive = HKEY_LOCAL_MACHINE;
            else if (parts[0] == "HKEY_CURRENT_USER") hive = HKEY_CURRENT_USER;
            else return;

            QString subKey = parts.mid(1).join("\\");

            // 打开注册表键
            HKEY hKey;
            LONG result = RegOpenKeyExA(hive, subKey.toStdString().c_str(), 0, KEY_WRITE, &hKey);
            if (result == ERROR_SUCCESS) {
                // 设置值
                const char *valueData = path.toStdString().c_str();
                result = RegSetValueExA(hKey, name.toStdString().c_str(), 0, REG_SZ,
                                        (const BYTE*)valueData, strlen(valueData) + 1);
                if (result == ERROR_SUCCESS) {
                    // 添加到树
                    if (tree == winlogonTree) {
                        addWinlogonItem(tree, parentItem, name, path, location);
                    } else {
                        // 修复：当在空白处添加时，parentItem 为 nullptr
                        // 需要找到或创建对应的顶级节点
                        QTreeWidgetItem *targetParent = parentItem;
                        if (!targetParent) {
                            // 查找或创建顶级节点
                            QString locationDesc = registryLocationDescriptions.value(location, "");
                            for (int i = 0; i < tree->topLevelItemCount(); i++) {
                                QTreeWidgetItem *topItem = tree->topLevelItem(i);
                                if (topItem->text(0) == locationDesc) {
                                    targetParent = topItem;
                                    break;
                                }
                            }

                            // 如果没有找到，创建新的顶级节点
                            if (!targetParent) {
                                targetParent = new QTreeWidgetItem(tree);
                                targetParent->setText(0, locationDesc);
                                targetParent->setText(4, location);
                                targetParent->setToolTip(4, location);
                            }
                        }

                        addRegistryItem(targetParent, name, path, location);
                    }
                    QMessageBox::information(this, "成功", "启动项已添加");
                    refreshAll(); // 添加成功后刷新
                } else {
                    showDetailedError("设置注册表值", location, result);
                }
                RegCloseKey(hKey);
            } else {
                showDetailedError("打开注册表键", location, result);
            }
        }
    }

    void onLoadComplete() {
        // 更新UI
        updateUIWithLoadedData();

        // 隐藏进度对话框
        if (progressDialog && progressDialog->isVisible()) {
            progressDialog->hide();
        }
    }

    void refreshAll() {
        // 清空所有树
        systemRegistryTree->clear();
        wow64RegistryTree->clear();
        userRegistryTree->clear();
        winlogonTree->clear();
        startupFoldersTree->clear();

        // 重新加载所有数据
        loadAllStartupsAsync();
    }

    void performSearch() {
        QString searchText = searchEdit->text().trimmed();

        // 搜索所有树控件
        searchTree(systemRegistryTree, searchText);
        searchTree(wow64RegistryTree, searchText);
        searchTree(userRegistryTree, searchText);
        searchTree(winlogonTree, searchText);
        searchTree(startupFoldersTree, searchText);

    }

private:
    QTabWidget *tabWidget;
    QTreeWidget *systemRegistryTree;
    QTreeWidget *wow64RegistryTree;
    QTreeWidget *userRegistryTree;
    QTreeWidget *winlogonTree;
    QTreeWidget *startupFoldersTree;
    QPushButton *refreshButton;
    QProgressDialog *progressDialog = nullptr;
    QLineEdit *searchEdit;
    QPushButton *searchButton;
    DigitalSignatureVerifier signatureVerifier;

    // 注册表位置说明映射
    const QMap<QString, QString> registryLocationDescriptions = {
        {"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "系统启动程序 (所有用户)"},
        {"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "一次性系统启动程序"},
        {"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "系统服务启动程序"},
        {"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "一次性系统服务启动程序"},
        {"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "系统策略启动程序"},
        {"HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "32位系统启动程序"},
        {"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "用户启动程序 (当前用户)"},
        {"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "一次性用户启动程序"},
        {"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "用户服务启动程序"},
        {"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "一次性用户服务启动程序"},
        {"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "用户策略启动程序"},
        {"HKEY_CURRENT_USER\\Environment\\UserInitMprLogonScript", "用户登录脚本"},
        {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "系统登录设置"},
        {"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "用户登录设置"},
        {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad", "延迟启动项 (所有用户)"},
        {"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad", "延迟启动项 (当前用户)"}
    };

    // Winlogon键名说明映射
    const QMap<QString, QString> winlogonKeyDescriptions = {
        {"Shell", "系统启动时运行的shell程序"},
        {"Userinit", "用户登录时运行的程序"},
        {"Taskman", "任务管理器程序"},
        {"System", "系统启动时运行的程序"},
        {"AppSetup", "应用程序安装程序"},
        {"GinaDLL", "图形识别和验证动态链接库"},
        {"UIHost", "登录界面程序"},
        {"VmApplet", "虚拟机小程序"}
    };

    struct LoadedData {
        QList<QTreeWidgetItem*> systemRegistryItems;
        QList<QTreeWidgetItem*> wow64RegistryItems;
        QList<QTreeWidgetItem*> userRegistryItems;
        QList<QTreeWidgetItem*> winlogonItems;
        QList<QTreeWidgetItem*> startupFolderItems;
    };
    // 数字签名状态颜色映射
    const QMap<QString, QColor> signatureColorMap = {
        {"有效", Qt::darkGreen},
        {"无效", Qt::red},
        {"未签名", Qt::darkGray},
        {"无法验证", QColor(255, 165, 0)}, // 橙色
        {"证书已吊销", QColor(255, 0, 255)}, // 紫色
        {"证书已过期", QColor(255, 165, 0)}, // 橙色
        {"证书不受信任", QColor(255, 165, 0)} // 橙色
    };

    LoadedData loadedData;

    QString verifyDigitalSignature(const QString &filePath) {
        SignatureInfo info = signatureVerifier.verifySignature(filePath);

        // 构建简洁的签名状态和签名者信息
        QString statusText = info.status;

        // 如果状态是"有效"但证书已过期，则显示为"过期签名"
        if (info.status == "有效" && info.signTime < QDateTime::currentDateTime()) {
            statusText = "过期签名";
        }

        // 构建最终显示字符串
        QString result = statusText;

        if (!info.signer.isEmpty()) {
            result += "：" + info.signer;
        }

        return result;
    }

    void setupUI() {
        resize(1400, 800);
        setWindowTitle("系统自启动管理器");

        QWidget *centralWidget = new QWidget(this);
        QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

        // 添加搜索控件
        QHBoxLayout *searchLayout = new QHBoxLayout();
        searchEdit = new QLineEdit(this);
        searchEdit->setPlaceholderText("搜索启动项...");
        searchLayout->addWidget(searchEdit);

        searchButton = new QPushButton("搜索", this);
        searchLayout->addWidget(searchButton);

        QPushButton *clearSearchButton = new QPushButton("清除搜索", this);
        searchLayout->addWidget(clearSearchButton);

        mainLayout->addLayout(searchLayout);

        // 连接搜索信号
        connect(searchButton, &QPushButton::clicked, this, &StartupManager::performSearch);
        connect(clearSearchButton, &QPushButton::clicked, this, [this]() {
            searchEdit->clear();
            performSearch(); // 清除搜索后重新执行搜索以显示所有项
        });
        connect(searchEdit, &QLineEdit::returnPressed, this, &StartupManager::performSearch);

        tabWidget = new QTabWidget(this);

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

        mainLayout->addWidget(tabWidget);

        // 系统自启动标签页
        QWidget *systemTab = new QWidget;
        QVBoxLayout *systemLayout = new QVBoxLayout(systemTab);
        systemRegistryTree = createTree({"", "名称", "路径", "描述", "位置说明", "数字签名"}, true);
        setupTreeContextMenu(systemRegistryTree);
        systemLayout->addWidget(new QLabel("<b>系统自启动项 (所有用户)</b>"));
        systemLayout->addWidget(systemRegistryTree);
        tabWidget->addTab(systemTab, "系统自启动");

        // Wow64启动标签页
        QWidget *wow64Tab = new QWidget;
        QVBoxLayout *wow64Layout = new QVBoxLayout(wow64Tab);
        wow64RegistryTree = createTree({"", "名称", "路径", "描述", "位置说明", "数字签名"}, true);
        setupTreeContextMenu(wow64RegistryTree);
        wow64Layout->addWidget(new QLabel("<b>Wow64自启动项 (32位程序)</b>"));
        wow64Layout->addWidget(wow64RegistryTree);
        tabWidget->addTab(wow64Tab, "Wow64启动");

        // 用户自启动标签页
        QWidget *userTab = new QWidget;
        QVBoxLayout *userLayout = new QVBoxLayout(userTab);
        userRegistryTree = createTree({"", "名称", "路径", "描述", "位置说明", "数字签名"}, true);
        setupTreeContextMenu(userRegistryTree);
        userLayout->addWidget(new QLabel("<b>用户自启动项 (当前用户)</b>"));
        userLayout->addWidget(userRegistryTree);
        tabWidget->addTab(userTab, "用户自启动");

        // Winlogon启动标签页
        QWidget *winlogonTab = new QWidget;
        QVBoxLayout *winlogonLayout = new QVBoxLayout(winlogonTab);

        QLabel *warningLabel = new QLabel(
            "<b style='color: red;'>警告：</b>修改Winlogon启动项可能导致系统不稳定或无法启动！"
            "请确保您完全了解这些设置的作用后再进行修改。"
            );
        warningLabel->setWordWrap(true);
        warningLabel->setStyleSheet("background-color: #FFF8E1; padding: 10px; border: 1px solid #FFD54F;");
        winlogonLayout->addWidget(warningLabel);

        winlogonTree = createTree({"", "键名", "路径", "文件描述", "键名说明", "数字签名"}, true);
        setupTreeContextMenu(winlogonTree);
        winlogonLayout->addWidget(new QLabel("<b>Winlogon Shell启动项 (系统关键启动位置)</b>"));
        winlogonLayout->addWidget(winlogonTree);
        tabWidget->addTab(winlogonTab, "Winlogon启动");

        // 启动文件夹标签页
        QWidget *startupFoldersTab = new QWidget;
        QVBoxLayout *startupFoldersLayout = new QVBoxLayout(startupFoldersTab);
        startupFoldersTree = createTree({"", "名称", "目标路径", "描述", "位置", "数字签名"}, true);
        setupTreeContextMenu(startupFoldersTree);
        startupFoldersLayout->addWidget(new QLabel("<b>启动文件夹</b>"));
        startupFoldersLayout->addWidget(startupFoldersTree);
        tabWidget->addTab(startupFoldersTab, "启动文件夹");

        refreshButton = new QPushButton("刷新所有");
        connect(refreshButton, &QPushButton::clicked, this, &StartupManager::refreshAll);
        mainLayout->addWidget(refreshButton, 0, Qt::AlignRight);

        setCentralWidget(centralWidget);

        // 初始化进度对话框
        progressDialog = new QProgressDialog(this);
        progressDialog->setWindowTitle("加载中...");
        progressDialog->setLabelText("正在加载启动项...");
        progressDialog->setCancelButton(nullptr); // 隐藏取消按钮
        progressDialog->setRange(0, 0); // 不确定进度
        progressDialog->setAutoClose(true);
        progressDialog->setAutoReset(true);
        progressDialog->setMinimumDuration(0);

        // 设置窗口标志：不获取焦点、始终置顶、无任务栏按钮
        progressDialog->setWindowFlags(
            Qt::Dialog |
            Qt::CustomizeWindowHint |
            Qt::WindowTitleHint |
            Qt::WindowStaysOnTopHint |
            Qt::WindowDoesNotAcceptFocus
            );

        progressDialog->hide();
    }

    void updateSignatureColor(QTreeWidgetItem *item, const QString &signatureText) {
        // 提取状态字符串（第一行）
        QString status = signatureText.section('\n', 0, 0);

        // 查找对应的颜色
        QColor color = signatureColorMap.value(status, Qt::black);

        // 设置整行的文本颜色
        for (int i = 0; i < item->columnCount(); i++) {
            item->setForeground(i, QBrush(color));
        }

        // 为签名列设置更深的颜色
        item->setForeground(5, QBrush(color.darker(150)));
    }

    void editWinlogonItemDialog(QTreeWidgetItem *item) {
        QString keyName = item->text(1);
        QString currentValue = item->text(2);
        QString location = item->data(0, Qt::UserRole).toString();

        QDialog dialog(this);
        dialog.setWindowTitle("编辑Winlogon启动项");
        QFormLayout layout(&dialog);

        QLineEdit keyNameEdit(&dialog);
        keyNameEdit.setText(keyName);
        keyNameEdit.setReadOnly(true);
        layout.addRow("键名:", &keyNameEdit);

        QLineEdit pathEdit(&dialog);
        pathEdit.setText(currentValue);
        layout.addRow("路径:", &pathEdit);

        QDialogButtonBox buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, &dialog);
        layout.addRow(&buttonBox);

        connect(&buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(&buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted) {
            QString newValue = pathEdit.text().trimmed();

            if (newValue.isEmpty()) {
                QMessageBox::warning(this, "错误", "路径不能为空");
                return;
            }

            QStringList parts = location.split("\\");
            if (parts.size() < 2) return;

            HKEY hive = NULL;
            if (parts[0] == "HKEY_LOCAL_MACHINE") hive = HKEY_LOCAL_MACHINE;
            else if (parts[0] == "HKEY_CURRENT_USER") hive = HKEY_CURRENT_USER;
            else return;

            QString subKey = parts.mid(1).join("\\");

            HKEY hKey;
            LONG result = RegOpenKeyExA(hive, subKey.toStdString().c_str(), 0, KEY_WRITE, &hKey);
            if (result == ERROR_SUCCESS) {
                result = RegSetValueExA(hKey, keyName.toStdString().c_str(), 0, REG_SZ,
                                        (const BYTE*)newValue.toStdString().c_str(),
                                        newValue.length() + 1);
                if (result == ERROR_SUCCESS) {
                    item->setText(2, newValue);
                    item->setToolTip(2, newValue);

                    QString cleanPath = cleanFilePath(expandEnvironmentVariables(newValue));
                    QString description = getFileDescription(cleanPath);
                    item->setText(3, description);
                    item->setToolTip(3, description);

                    // 更新签名信息
                    QString signature = verifyDigitalSignature(cleanPath);
                    item->setText(5, signature);
                    item->setToolTip(5, signature);
                    updateSignatureColor(item, signature);

                    QMessageBox::information(this, "成功", "Winlogon启动项已更新");
                    refreshAll(); // 编辑成功后刷新
                } else {
                    showDetailedError("更新注册表值", location, result);
                }
                RegCloseKey(hKey);
            } else {
                showDetailedError("打开注册表键", location, result);
            }
        }
    }

    void editStartupFolderItemDialog(QTreeWidgetItem *item) {
        QString name = item->text(1);
        QString targetPath = item->text(2);
        QString filePath = item->data(0, Qt::UserRole).toString();

        // 从名称中移除".lnk"后缀（如果存在）
        if (name.endsWith(".lnk", Qt::CaseInsensitive)) {
            name.chop(4);
        }

        QDialog dialog(this);
        dialog.setWindowTitle("编辑启动文件夹项");
        QFormLayout layout(&dialog);

        QLineEdit nameEdit(&dialog);
        nameEdit.setText(name); // 显示不带".lnk"的名称
        layout.addRow("名称:", &nameEdit);

        QLineEdit pathEdit(&dialog);
        pathEdit.setText(targetPath);
        QPushButton browseButton("浏览...", &dialog);
        QHBoxLayout pathLayout;
        pathLayout.addWidget(&pathEdit);
        pathLayout.addWidget(&browseButton);
        layout.addRow("目标路径:", &pathLayout);

        QDialogButtonBox buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, &dialog);
        layout.addRow(&buttonBox);

        connect(&browseButton, &QPushButton::clicked, [&]() {
            QString file = QFileDialog::getOpenFileName(this, "选择可执行文件", "", "可执行文件 (*.exe);;所有文件 (*.*)");
            if (!file.isEmpty()) {
                pathEdit.setText(file);
            }
        });

        connect(&buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(&buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted) {
            QString newName = nameEdit.text().trimmed();
            QString newTarget = pathEdit.text().trimmed();

            if (newName.isEmpty() || newTarget.isEmpty()) {
                QMessageBox::warning(this, "错误", "名称和目标路径不能为空");
                return;
            }

            // 确保名称以".lnk"结尾
            if (!newName.endsWith(".lnk", Qt::CaseInsensitive)) {
                newName += ".lnk";
            }

            // 创建新的快捷方式路径
            QFileInfo oldFileInfo(filePath);
            QString newFilePath = oldFileInfo.absolutePath() + "/" + newName;

            // 如果名称改变，删除旧文件
            if (newName != oldFileInfo.fileName()) {
                if (!QFile::remove(filePath)) {
                    showDetailedError("删除旧文件", filePath, GetLastError());
                    return;
                }
            }

            // 创建新的快捷方式
            if (createShortcut(newFilePath, newTarget)) {
                // 更新UI项
                item->setText(1, newName);
                item->setText(2, newTarget);
                item->setData(0, Qt::UserRole, newFilePath);

                QString cleanPath = cleanFilePath(expandEnvironmentVariables(newTarget));
                QString description = getFileDescription(cleanPath);
                item->setText(3, description);
                item->setToolTip(3, description);

                // 更新签名信息
                QString signature = verifyDigitalSignature(cleanPath);
                item->setText(5, signature);
                item->setToolTip(5, signature);
                updateSignatureColor(item, signature);

                QMessageBox::information(this, "成功", "启动项已更新");
                // 不需要刷新整个树，只需更新该项
            } else {
                showDetailedError("创建快捷方式", newFilePath, GetLastError());
            }
        }
    }

    void addWinlogonItemDialog(QTreeWidgetItem *parentItem) {
        QDialog dialog(this);
        dialog.setWindowTitle("添加Winlogon启动项");
        QFormLayout layout(&dialog);

        QComboBox keyNameCombo(&dialog);
        keyNameCombo.addItems({"Userinit", "Shell", "Taskman", "System", "AppSetup", "GinaDLL", "UIHost", "VmApplet"});
        layout.addRow("键名:", &keyNameCombo);

        QLineEdit pathEdit(&dialog);
        QPushButton browseButton("浏览...", &dialog);
        QHBoxLayout pathLayout;
        pathLayout.addWidget(&pathEdit);
        pathLayout.addWidget(&browseButton);
        layout.addRow("路径:", &pathLayout);

        QComboBox hkeyCombo(&dialog);
        hkeyCombo.addItem("HKEY_LOCAL_MACHINE");
        hkeyCombo.addItem("HKEY_CURRENT_USER");
        layout.addRow("位置:", &hkeyCombo);

        QDialogButtonBox buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, &dialog);
        layout.addRow(&buttonBox);

        connect(&browseButton, &QPushButton::clicked, [&]() {
            QString file = QFileDialog::getOpenFileName(this, "选择可执行文件", "", "可执行文件 (*.exe);;所有文件 (*.*)");
            if (!file.isEmpty()) {
                pathEdit.setText(file);
            }
        });

        connect(&buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(&buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted) {
            QString keyName = keyNameCombo.currentText();
            QString path = pathEdit.text().trimmed();
            QString hkey = hkeyCombo.currentText();

            if (path.isEmpty()) {
                QMessageBox::warning(this, "错误", "路径不能为空");
                return;
            }

            QString location = hkey + "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

            HKEY hive = (hkey == "HKEY_LOCAL_MACHINE") ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
            HKEY hKey;
            LONG result = RegOpenKeyExA(hive, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ | KEY_WRITE, &hKey);
            if (result == ERROR_SUCCESS) {
                char existingValue[1024];
                DWORD size = sizeof(existingValue);
                DWORD type;
                result = RegQueryValueExA(hKey, keyName.toStdString().c_str(), NULL, &type, (LPBYTE)existingValue, &size);

                QString newValue;
                if (result == ERROR_SUCCESS && type == REG_SZ) {
                    QString existingStr = QString::fromLocal8Bit(existingValue);
                    if (!existingStr.isEmpty() && !existingStr.endsWith(",")) {
                        existingStr += ",";
                    }
                    newValue = existingStr + path;
                } else {
                    newValue = path;
                }

                result = RegSetValueExA(hKey, keyName.toStdString().c_str(), 0, REG_SZ,
                                        (const BYTE*)newValue.toStdString().c_str(),
                                        newValue.length() + 1);
                if (result == ERROR_SUCCESS) {
                    addWinlogonItem(winlogonTree, parentItem, keyName, newValue, location);
                    QMessageBox::information(this, "成功", "Winlogon启动项已添加");
                    refreshAll(); // 添加成功后刷新
                } else {
                    showDetailedError("设置注册表值", location, result);
                }
                RegCloseKey(hKey);
            } else {
                showDetailedError("打开注册表键", location, result);
            }
        }
    }

    void addStartupFolderItemDialog(QTreeWidgetItem *parentItem) {
        QDialog dialog(this);
        dialog.setWindowTitle("添加快捷方式到启动文件夹");
        QFormLayout layout(&dialog);

        QLineEdit nameEdit(&dialog);
        layout.addRow("名称:", &nameEdit);

        QLineEdit targetEdit(&dialog);
        QPushButton browseButton("浏览...", &dialog);
        QHBoxLayout targetLayout;
        targetLayout.addWidget(&targetEdit);
        targetLayout.addWidget(&browseButton);
        layout.addRow("目标:", &targetLayout);

        QComboBox folderCombo(&dialog);
        folderCombo.addItem("所有用户启动文件夹");
        folderCombo.addItem("当前用户启动文件夹");
        layout.addRow("位置:", &folderCombo);

        QDialogButtonBox buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, &dialog);
        layout.addRow(&buttonBox);

        connect(&browseButton, &QPushButton::clicked, [&]() {
            QString file = QFileDialog::getOpenFileName(this, "选择可执行文件", "", "可执行文件 (*.exe);;所有文件 (*.*)");
            if (!file.isEmpty()) {
                targetEdit.setText(file);
            }
        });

        connect(&buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(&buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted) {
            QString name = nameEdit.text().trimmed();
            QString target = targetEdit.text().trimmed();
            QString folderType = folderCombo.currentText();

            if (name.isEmpty() || target.isEmpty()) {
                QMessageBox::warning(this, "错误", "名称和目标不能为空");
                return;
            }

            // 确保名称以".lnk"结尾
            if (!name.endsWith(".lnk", Qt::CaseInsensitive)) {
                name += ".lnk";
            }

            // 获取启动文件夹路径
            QString folderPath;
            if (folderType == "所有用户启动文件夹") {
                wchar_t path[MAX_PATH];
                if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, path) == S_OK) {
                    folderPath = QString::fromWCharArray(path);
                }
            } else {
                wchar_t path[MAX_PATH];
                if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path) == S_OK) {
                    folderPath = QString::fromWCharArray(path);
                }
            }

            if (folderPath.isEmpty()) {
                QMessageBox::warning(this, "错误", "无法获取启动文件夹路径");
                return;
            }

            // 创建快捷方式
            QString shortcutPath = folderPath + "\\" + name + ".lnk";
            if (createShortcut(shortcutPath, target)) {
                // 添加到树
                QTreeWidgetItem *rootItem = nullptr;
                if (folderType == "所有用户启动文件夹") {
                    for (int i = 0; i < startupFoldersTree->topLevelItemCount(); i++) {
                        if (startupFoldersTree->topLevelItem(i)->text(0) == "所有用户启动文件夹") {
                            rootItem = startupFoldersTree->topLevelItem(i);
                            break;
                        }
                    }
                } else {
                    for (int i = 0; i < startupFoldersTree->topLevelItemCount(); i++) {
                        if (startupFoldersTree->topLevelItem(i)->text(0) == "当前用户启动文件夹") {
                            rootItem = startupFoldersTree->topLevelItem(i);
                            break;
                        }
                    }
                }

                if (rootItem) {
                    QTreeWidgetItem *item = new QTreeWidgetItem(rootItem);
                    QString cleanPath = cleanFilePath(expandEnvironmentVariables(target));
                    QIcon icon = getFileIcon(cleanPath);
                    QString description = getFileDescription(cleanPath);
                    QString signature = verifyDigitalSignature(cleanPath);

                    item->setIcon(0, icon);
                    item->setText(1, name + ".lnk");
                    item->setText(2, target);
                    item->setToolTip(2, target);
                    item->setText(3, description);
                    item->setToolTip(3, description);
                    item->setText(4, folderPath);
                    item->setData(0, Qt::UserRole, shortcutPath);

                    // 设置签名信息
                    item->setText(5, signature);
                    item->setToolTip(5, signature);
                    updateSignatureColor(item, signature);

                    QMessageBox::information(this, "成功", "启动项已添加到启动文件夹");
                    refreshAll();
                }
            } else {
                showDetailedError("创建快捷方式", shortcutPath, GetLastError());
            }
        }
    }

    void setupTreeContextMenu(QTreeWidget *tree) {
        tree->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(tree, &QTreeWidget::customContextMenuRequested, [=](const QPoint &pos) {
            QTreeWidgetItem *item = tree->itemAt(pos);
            int column = tree->currentColumn();
            QMenu menu;

            if (item) {
                if (column == 4) {
                    QString location = item->text(4);

                    QAction *copyPathAction = menu.addAction("复制注册表路径");
                    QAction *openRegeditAction = menu.addAction("打开注册表编辑器");

                    connect(copyPathAction, &QAction::triggered, [=]() {
                        QApplication::clipboard()->setText(location);
                    });

                    connect(openRegeditAction, &QAction::triggered, [=]() {
                        openRegistryEditor(location);
                    });
                }
                else if (column == 2) {
                    QString filePath = item->text(2);

                    // 获取清理后的命令行（不带参数）
                    QString cleanCommandLine = cleanFilePath(expandEnvironmentVariables(filePath));

                    QAction *copyQuotedPathAction = menu.addAction("复制路径（带引号）");
                    QAction *copyCommandLineAction = menu.addAction("复制命令行");
                    QAction *openExplorerAction = menu.addAction("打开文件位置");

                    connect(copyQuotedPathAction, &QAction::triggered, [=]() {
                        QApplication::clipboard()->setText("\"" + filePath + "\"");
                    });

                    connect(copyCommandLineAction, &QAction::triggered, [=]() {
                        // 复制清理过的命令行（不带参数）
                        QApplication::clipboard()->setText(cleanCommandLine);
                    });

                    connect(openExplorerAction, &QAction::triggered, [=]() {
                        openFileLocation(filePath);
                    });
                }
                else {
                    QAction *addAction = menu.addAction("添加");
                    QAction *editAction = menu.addAction("编辑");
                    QAction *deleteAction = menu.addAction("删除");

                    bool isCategory = (item->childCount() > 0);
                    bool isLeaf = (item->childCount() == 0);

                    addAction->setEnabled(true);
                    editAction->setEnabled(isLeaf);
                    deleteAction->setEnabled(isLeaf);

                    connect(addAction, &QAction::triggered, [=]() { onAddItem(tree, item); });
                    connect(editAction, &QAction::triggered, [=]() { onEditItem(tree, item); });
                    connect(deleteAction, &QAction::triggered, [=]() { onDeleteItem(tree, item); });
                }

                // 添加签名验证菜单项
                if (column == 5) {
                    menu.addSeparator();

                    QAction *verifyAction = menu.addAction("验证数字签名");
                    connect(verifyAction, &QAction::triggered, [=]() {
                        QString filePath = item->text(2);
                        if (filePath.isEmpty()) return;

                        filePath = expandEnvironmentVariables(filePath);
                        QString signatureDetails = signatureVerifier.getSignatureDetails(filePath);

                        QMessageBox::information(this, "数字签名详细信息", signatureDetails);
                    });

                    QAction *copySignatureAction = menu.addAction("复制签名信息");
                    connect(copySignatureAction, &QAction::triggered, [=]() {
                        QApplication::clipboard()->setText(item->text(5));
                    });
                }
            } else {
                QAction *addAction = menu.addAction("添加");
                connect(addAction, &QAction::triggered, [=]() { onAddItem(tree, nullptr); });
            }

            menu.exec(tree->viewport()->mapToGlobal(pos));
        });
    }

    QList<QTreeWidgetItem*> loadSystemRegistryStartupsData() {
        QList<QTreeWidgetItem*> items;

        // 创建顶级分类节点
        QTreeWidgetItem *runCategory = new QTreeWidgetItem();
        runCategory->setText(0, "Run");
        QTreeWidgetItem *runOnceCategory = new QTreeWidgetItem();
        runOnceCategory->setText(0, "RunOnce");
        QTreeWidgetItem *runServicesCategory = new QTreeWidgetItem();
        runServicesCategory->setText(0, "RunServices");
        QTreeWidgetItem *runServicesOnceCategory = new QTreeWidgetItem();
        runServicesOnceCategory->setText(0, "RunServicesOnce");
        QTreeWidgetItem *policiesCategory = new QTreeWidgetItem();
        policiesCategory->setText(0, "Policies\\Explorer\\Run");
        QTreeWidgetItem *delayedCategory = new QTreeWidgetItem();
        delayedCategory->setText(0, "Delayed Auto Start");

        // 系统级自启动注册表位置 (所有用户)
        const std::vector<std::pair<HKEY, QString>> locations = {
            {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
            {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"},
            {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"},
            {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"},
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad"}
        };

        for (const auto& [hive, path] : locations) {
            HKEY hKey;
            LONG result = RegOpenKeyExA(hive, path.toStdString().c_str(), 0, KEY_READ, &hKey);
            if (result == ERROR_SUCCESS) {
                DWORD index = 0;
                CHAR valueName[256];
                DWORD valueNameSize = sizeof(valueName);
                DWORD valueType;
                BYTE valueData[1024];
                DWORD valueDataSize = sizeof(valueData);

                while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL,
                                     &valueType, valueData, &valueDataSize) == ERROR_SUCCESS) {
                    if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                        QString name = QString::fromLocal8Bit(valueName);
                        QString filePath = QString::fromLocal8Bit((char*)valueData);
                        QString location = "HKEY_LOCAL_MACHINE\\" + path;

                        // 确定分类
                        QTreeWidgetItem *parentItem = nullptr;
                        if (path.contains("RunOnce")) {
                            parentItem = runOnceCategory;
                        } else if (path.contains("RunServices")) {
                            if (path.contains("RunServicesOnce")) {
                                parentItem = runServicesOnceCategory;
                            } else {
                                parentItem = runServicesCategory;
                            }
                        } else if (path.contains("Policies")) {
                            parentItem = policiesCategory;
                        } else if (path.contains("DelayLoad")) {
                            parentItem = delayedCategory;
                        } else {
                            parentItem = runCategory;
                        }

                        // 创建子节点
                        QTreeWidgetItem *item = new QTreeWidgetItem(parentItem);
                        QString locationDesc = registryLocationDescriptions.value(location, "");
                        QString cleanPath = cleanFilePath(expandEnvironmentVariables(filePath));
                        QString description = getFileDescription(cleanPath);
                        QIcon icon = getFileIcon(cleanPath);
                        QString signature = verifyDigitalSignature(cleanPath);

                        item->setIcon(0, icon);
                        item->setText(1, name);
                        item->setText(2, filePath);
                        item->setToolTip(2, filePath);
                        item->setText(3, description);
                        item->setToolTip(3, description);
                        item->setText(4, location);
                        item->setToolTip(4, location);
                        item->setText(5, signature);
                        item->setToolTip(5, signature);
                        item->setData(0, Qt::UserRole, location);

                        updateSignatureColor(item, signature);
                    }

                    valueNameSize = sizeof(valueName);
                    valueDataSize = sizeof(valueData);
                    index++;
                }
                RegCloseKey(hKey);
            }
        }

        // 添加顶级节点
        if (runCategory->childCount() > 0) items.append(runCategory);
        if (runOnceCategory->childCount() > 0) items.append(runOnceCategory);
        if (runServicesCategory->childCount() > 0) items.append(runServicesCategory);
        if (runServicesOnceCategory->childCount() > 0) items.append(runServicesOnceCategory);
        if (policiesCategory->childCount() > 0) items.append(policiesCategory);
        if (delayedCategory->childCount() > 0) items.append(delayedCategory);

        return items;
    }

    QList<QTreeWidgetItem*> loadWow64RegistryStartupsData() {
        QList<QTreeWidgetItem*> items;

        // 创建顶级分类节点
        QTreeWidgetItem *runCategory = new QTreeWidgetItem();
        runCategory->setText(0, "Run");
        QTreeWidgetItem *runOnceCategory = new QTreeWidgetItem();
        runOnceCategory->setText(0, "RunOnce");
        QTreeWidgetItem *runServicesCategory = new QTreeWidgetItem();
        runServicesCategory->setText(0, "RunServices");
        QTreeWidgetItem *runServicesOnceCategory = new QTreeWidgetItem();
        runServicesOnceCategory->setText(0, "RunServicesOnce");
        QTreeWidgetItem *policiesCategory = new QTreeWidgetItem();
        policiesCategory->setText(0, "Policies\\Explorer\\Run");
        QTreeWidgetItem *delayedCategory = new QTreeWidgetItem();
        delayedCategory->setText(0, "Delayed Auto Start");

        // Wow64自启动注册表位置 (32位程序)
        const std::vector<std::pair<HKEY, QString>> locations = {
            {HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
            {HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices"},
            {HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"},
            {HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"},
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad"}
        };

        for (const auto& [hive, path] : locations) {
            HKEY hKey;
            LONG result = RegOpenKeyExA(hive, path.toStdString().c_str(), 0, KEY_READ, &hKey);
            if (result == ERROR_SUCCESS) {
                DWORD index = 0;
                CHAR valueName[256];
                DWORD valueNameSize = sizeof(valueName);
                DWORD valueType;
                BYTE valueData[1024];
                DWORD valueDataSize = sizeof(valueData);

                while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL,
                                     &valueType, valueData, &valueDataSize) == ERROR_SUCCESS) {
                    if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                        QString name = QString::fromLocal8Bit(valueName);
                        QString filePath = QString::fromLocal8Bit((char*)valueData);
                        QString location = "HKEY_LOCAL_MACHINE\\" + path;

                        // 确定分类
                        QTreeWidgetItem *parentItem = nullptr;
                        if (path.contains("RunOnce")) {
                            parentItem = runOnceCategory;
                        } else if (path.contains("RunServices")) {
                            if (path.contains("RunServicesOnce")) {
                                parentItem = runServicesOnceCategory;
                            } else {
                                parentItem = runServicesCategory;
                            }
                        } else if (path.contains("Policies")) {
                            parentItem = policiesCategory;
                        } else if (path.contains("DelayLoad")) {
                            parentItem = delayedCategory;
                        } else {
                            parentItem = runCategory;
                        }

                        // 创建子节点
                        QTreeWidgetItem *item = new QTreeWidgetItem(parentItem);
                        QString locationDesc = registryLocationDescriptions.value(location, "");
                        QString cleanPath = cleanFilePath(expandEnvironmentVariables(filePath));
                        QString description = getFileDescription(cleanPath);
                        QIcon icon = getFileIcon(cleanPath);
                        QString signature = verifyDigitalSignature(cleanPath);

                        item->setIcon(0, icon);
                        item->setText(1, name);
                        item->setText(2, filePath);
                        item->setToolTip(2, filePath);
                        item->setText(3, description);
                        item->setToolTip(3, description);
                        item->setText(4, location);
                        item->setToolTip(4, location);
                        item->setText(5, signature);
                        item->setToolTip(5, signature);
                        item->setData(0, Qt::UserRole, location);

                        updateSignatureColor(item, signature);
                    }

                    valueNameSize = sizeof(valueName);
                    valueDataSize = sizeof(valueData);
                    index++;
                }
                RegCloseKey(hKey);
            }
        }

        // 添加顶级节点
        if (runCategory->childCount() > 0) items.append(runCategory);
        if (runOnceCategory->childCount() > 0) items.append(runOnceCategory);
        if (runServicesCategory->childCount() > 0) items.append(runServicesCategory);
        if (runServicesOnceCategory->childCount() > 0) items.append(runServicesOnceCategory);
        if (policiesCategory->childCount() > 0) items.append(policiesCategory);
        if (delayedCategory->childCount() > 0) items.append(delayedCategory);

        return items;
    }

    QList<QTreeWidgetItem*> loadUserRegistryStartupsData() {
        QList<QTreeWidgetItem*> items;

        // 创建顶级分类节点
        QTreeWidgetItem *runCategory = new QTreeWidgetItem();
        runCategory->setText(0, "Run");
        QTreeWidgetItem *runOnceCategory = new QTreeWidgetItem();
        runOnceCategory->setText(0, "RunOnce");
        QTreeWidgetItem *runServicesCategory = new QTreeWidgetItem();
        runServicesCategory->setText(0, "RunServices");
        QTreeWidgetItem *runServicesOnceCategory = new QTreeWidgetItem();
        runServicesOnceCategory->setText(0, "RunServicesOnce");
        QTreeWidgetItem *policiesCategory = new QTreeWidgetItem();
        policiesCategory->setText(0, "Policies\\Explorer\\Run");
        QTreeWidgetItem *logonScriptCategory = new QTreeWidgetItem();
        logonScriptCategory->setText(0, "UserInitMprLogonScript");
        QTreeWidgetItem *delayedCategory = new QTreeWidgetItem();
        delayedCategory->setText(0, "Delayed Auto Start");

        // 用户级自启动注册表位置 (当前用户)
        const std::vector<std::pair<HKEY, QString>> locations = {
            {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
            {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"},
            {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"},
            {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"},
            {HKEY_CURRENT_USER, "Environment\\UserInitMprLogonScript"},
            {HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DelayLoad"}
        };

        for (const auto& [hive, path] : locations) {
            HKEY hKey;
            LONG result = RegOpenKeyExA(hive, path.toStdString().c_str(), 0, KEY_READ, &hKey);
            if (result == ERROR_SUCCESS) {
                DWORD index = 0;
                CHAR valueName[256];
                DWORD valueNameSize = sizeof(valueName);
                DWORD valueType;
                BYTE valueData[1024];
                DWORD valueDataSize = sizeof(valueData);

                while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL,
                                     &valueType, valueData, &valueDataSize) == ERROR_SUCCESS) {
                    if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                        QString name = QString::fromLocal8Bit(valueName);
                        QString filePath = QString::fromLocal8Bit((char*)valueData);
                        QString location = "HKEY_CURRENT_USER\\" + path;

                        // 确定分类
                        QTreeWidgetItem *parentItem = nullptr;
                        if (path.contains("RunOnce")) {
                            parentItem = runOnceCategory;
                        } else if (path.contains("RunServices")) {
                            if (path.contains("RunServicesOnce")) {
                                parentItem = runServicesOnceCategory;
                            } else {
                                parentItem = runServicesCategory;
                            }
                        } else if (path.contains("Policies")) {
                            parentItem = policiesCategory;
                        } else if (path.contains("UserInitMprLogonScript")) {
                            parentItem = logonScriptCategory;
                        } else if (path.contains("DelayLoad")) {
                            parentItem = delayedCategory;
                        } else {
                            parentItem = runCategory;
                        }

                        // 创建子节点
                        QTreeWidgetItem *item = new QTreeWidgetItem(parentItem);
                        QString locationDesc = registryLocationDescriptions.value(location, "");
                        QString cleanPath = cleanFilePath(expandEnvironmentVariables(filePath));
                        QString description = getFileDescription(cleanPath);
                        QIcon icon = getFileIcon(cleanPath);
                        QString signature = verifyDigitalSignature(cleanPath);

                        item->setIcon(0, icon);
                        item->setText(1, name);
                        item->setText(2, filePath);
                        item->setToolTip(2, filePath);
                        item->setText(3, description);
                        item->setToolTip(3, description);
                        item->setText(4, location);
                        item->setToolTip(4, location);
                        item->setText(5, signature);
                        item->setToolTip(5, signature);
                        item->setData(0, Qt::UserRole, location);

                        updateSignatureColor(item, signature);
                    }

                    valueNameSize = sizeof(valueName);
                    valueDataSize = sizeof(valueData);
                    index++;
                }
                RegCloseKey(hKey);
            }
        }

        // 添加顶级节点
        if (runCategory->childCount() > 0) items.append(runCategory);
        if (runOnceCategory->childCount() > 0) items.append(runOnceCategory);
        if (runServicesCategory->childCount() > 0) items.append(runServicesCategory);
        if (runServicesOnceCategory->childCount() > 0) items.append(runServicesOnceCategory);
        if (policiesCategory->childCount() > 0) items.append(policiesCategory);
        if (logonScriptCategory->childCount() > 0) items.append(logonScriptCategory);
        if (delayedCategory->childCount() > 0) items.append(delayedCategory);

        return items;
    }

    QList<QTreeWidgetItem*> loadWinlogonStartupsData() {
        QList<QTreeWidgetItem*> items;

        // 创建顶级分类节点
        QTreeWidgetItem *systemRoot = new QTreeWidgetItem();
        systemRoot->setText(0, "系统 (HKEY_LOCAL_MACHINE)");
        QTreeWidgetItem *userRoot = new QTreeWidgetItem();
        userRoot->setText(0, "用户 (HKEY_CURRENT_USER)");

        // Winlogon Shell 注册表位置
        const std::vector<std::pair<HKEY, QString>> locations = {
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"},
            {HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}
        };

        // 需要检查的键名
        const std::vector<QString> keys = {
            "Shell", "Userinit", "Taskman", "System",
            "AppSetup", "GinaDLL", "UIHost", "VmApplet"
        };

        for (const auto& [hive, path] : locations) {
            HKEY hKey;
            if (RegOpenKeyExA(hive, path.toStdString().c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                for (const auto& key : keys) {
                    CHAR valueData[1024];
                    DWORD valueDataSize = sizeof(valueData);
                    DWORD valueType;

                    if (RegQueryValueExA(hKey, key.toStdString().c_str(), NULL,
                                         &valueType, (LPBYTE)valueData, &valueDataSize) == ERROR_SUCCESS) {
                        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                            QString value = QString::fromLocal8Bit(valueData);
                            QString location;
                            if (hive == HKEY_CURRENT_USER) location = "HKEY_CURRENT_USER\\";
                            else location = "HKEY_LOCAL_MACHINE\\";
                            location += path;

                            // 分割多个可执行文件（用逗号分隔）
                            QStringList exePaths = value.split(',', Qt::SkipEmptyParts);

                            for (const QString &exePath : exePaths) {
                                QString trimmedPath = exePath.trimmed();
                                if (trimmedPath.isEmpty()) continue;

                                // 确定父节点
                                QTreeWidgetItem *rootItem = (hive == HKEY_LOCAL_MACHINE) ? systemRoot : userRoot;

                                // 查找或创建键节点
                                QTreeWidgetItem *keyItem = nullptr;
                                for (int i = 0; i < rootItem->childCount(); i++) {
                                    if (rootItem->child(i)->text(0) == key) {
                                        keyItem = rootItem->child(i);
                                        break;
                                    }
                                }

                                if (!keyItem) {
                                    keyItem = new QTreeWidgetItem(rootItem);
                                    keyItem->setText(0, key);
                                }

                                // 创建值节点
                                QTreeWidgetItem *item = new QTreeWidgetItem(keyItem);
                                QString expandedPath = expandEnvironmentVariables(trimmedPath);
                                QString cleanPath = cleanFilePath(expandedPath);
                                QIcon icon = getFileIcon(cleanPath);
                                QString description = getFileDescription(cleanPath);
                                QString keyDescription = winlogonKeyDescriptions.value(key, "未知键");
                                QString signature = verifyDigitalSignature(cleanPath);

                                item->setIcon(0, icon);
                                item->setText(1, key);
                                item->setText(2, trimmedPath);
                                item->setToolTip(2, trimmedPath);
                                item->setText(3, description);
                                item->setToolTip(3, description);
                                item->setText(4, keyDescription);
                                item->setText(5, signature);
                                item->setToolTip(5, signature);
                                item->setData(0, Qt::UserRole, location);

                                updateSignatureColor(item, signature);
                            }
                        }
                    }
                }
                RegCloseKey(hKey);
            }
        }

        // 添加顶级节点
        if (systemRoot->childCount() > 0) items.append(systemRoot);
        if (userRoot->childCount() > 0) items.append(userRoot);

        return items;
    }

    QList<QTreeWidgetItem*> loadStartupFoldersData() {
        QList<QTreeWidgetItem*> items;

        // 创建顶级分类节点
        QTreeWidgetItem *allUsersFolder = new QTreeWidgetItem();
        allUsersFolder->setText(0, "所有用户启动文件夹");
        QTreeWidgetItem *currentUserFolder = new QTreeWidgetItem();
        currentUserFolder->setText(0, "当前用户启动文件夹");

        // 所有用户启动文件夹
        wchar_t allUsersPath[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, allUsersPath) == S_OK) {
            loadStartupFolderItems(allUsersFolder, QString::fromWCharArray(allUsersPath));
        } else {
            // 即使获取路径失败也创建节点
            allUsersFolder->setText(4, "无法访问所有用户启动文件夹");
        }

        // 当前用户启动文件夹
        wchar_t currentUserPath[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, currentUserPath) == S_OK) {
            loadStartupFolderItems(currentUserFolder, QString::fromWCharArray(currentUserPath));
        } else {
            // 即使获取路径失败也创建节点
            currentUserFolder->setText(4, "无法访问当前用户启动文件夹");
        }

        // 总是添加顶级节点，即使为空
        items.append(allUsersFolder);
        items.append(currentUserFolder);

        return items;
    }

    void loadStartupFolderItems(QTreeWidgetItem *parent, const QString &folderPath) {
        QDir dir(folderPath);
        QFileInfoList files = dir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot);

        foreach (const QFileInfo &fileInfo, files) {
            QString filePath = fileInfo.absoluteFilePath();
            QString fileName = fileInfo.fileName();

            // 处理快捷方式
            if (fileInfo.suffix().compare("lnk", Qt::CaseInsensitive) == 0) {
                IShellLinkW *psl = NULL;
                wchar_t targetPath[MAX_PATH];

                if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                                               IID_IShellLinkW, (void**)&psl))) {
                    IPersistFile *ppf = NULL;
                    if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
                        if (SUCCEEDED(ppf->Load(filePath.toStdWString().c_str(), STGM_READ))) {
                            if (SUCCEEDED(psl->GetPath(targetPath, MAX_PATH, NULL, 0))) {
                                QString target = QString::fromWCharArray(targetPath);

                                QTreeWidgetItem *item = new QTreeWidgetItem(parent);
                                QString cleanPath = cleanFilePath(expandEnvironmentVariables(target));
                                QIcon icon = getFileIcon(cleanPath);
                                QString description = getFileDescription(cleanPath);
                                QString signature = verifyDigitalSignature(cleanPath);

                                item->setIcon(0, icon);
                                item->setText(1, fileName);
                                item->setText(2, target);
                                item->setToolTip(2, target);
                                item->setText(3, description);
                                item->setToolTip(3, description);
                                item->setText(4, folderPath);
                                item->setData(0, Qt::UserRole, filePath);
                                item->setText(5, signature);
                                item->setToolTip(5, signature);

                                updateSignatureColor(item, signature);
                            }
                        }
                        ppf->Release();
                    }
                    psl->Release();
                }
            }
            // 处理可执行文件
            else if (fileInfo.suffix().compare("exe", Qt::CaseInsensitive) == 0) {
                QTreeWidgetItem *item = new QTreeWidgetItem(parent);
                QString cleanPath = cleanFilePath(expandEnvironmentVariables(filePath));
                QIcon icon = getFileIcon(cleanPath);
                QString description = getFileDescription(cleanPath);
                QString signature = verifyDigitalSignature(cleanPath);

                item->setIcon(0, icon);
                item->setText(1, fileName);
                item->setText(2, filePath);
                item->setToolTip(2, filePath);
                item->setText(3, description);
                item->setToolTip(3, description);
                item->setText(4, folderPath);
                item->setData(0, Qt::UserRole, filePath);
                item->setText(5, signature);
                item->setToolTip(5, signature);

                updateSignatureColor(item, signature);
            }
        }
    }

    void addRegistryItem(QTreeWidgetItem *parentItem, const QString &name,
                         const QString &filePath, const QString &location) {
        QString locationDesc = registryLocationDescriptions.value(location, "");
        if (parentItem->text(4).isEmpty()) {
            parentItem->setText(4, locationDesc);
            parentItem->setToolTip(4, locationDesc);
        }

        QTreeWidgetItem *item = new QTreeWidgetItem(parentItem);
        QString expandedPath = expandEnvironmentVariables(filePath);
        QString cleanPath = cleanFilePath(expandedPath);
        QIcon icon = getFileIcon(cleanPath);
        QString description = getFileDescription(cleanPath);
        QString signature = verifyDigitalSignature(cleanPath);

        item->setIcon(0, icon);
        item->setText(1, name);
        item->setText(2, filePath);
        item->setToolTip(2, filePath);
        item->setText(3, description);
        item->setToolTip(3, description);
        item->setText(4, location);
        item->setToolTip(4, location);
        item->setText(5, signature);
        item->setToolTip(5, signature);
        item->setData(0, Qt::UserRole, location);

        updateSignatureColor(item, signature);
    }

    void addWinlogonItem(QTreeWidget *tree, QTreeWidgetItem *parentItem,
                         const QString &name, const QString &filePath,
                         const QString &location) {
        QTreeWidgetItem *rootItem = nullptr;
        if (location.contains("HKEY_LOCAL_MACHINE")) {
            for (int i = 0; i < tree->topLevelItemCount(); i++) {
                if (tree->topLevelItem(i)->text(0) == "系统 (HKEY_LOCAL_MACHINE)") {
                    rootItem = tree->topLevelItem(i);
                    break;
                }
            }
        } else {
            for (int i = 0; i < tree->topLevelItemCount(); i++) {
                if (tree->topLevelItem(i)->text(0) == "用户 (HKEY_CURRENT_USER)") {
                    rootItem = tree->topLevelItem(i);
                    break;
                }
            }
        }

        if (!rootItem) {
            rootItem = new QTreeWidgetItem(tree);
            rootItem->setText(0, location.contains("HKEY_LOCAL_MACHINE") ?
                                     "系统 (HKEY_LOCAL_MACHINE)" : "用户 (HKEY_CURRENT_USER)");
        }

        QTreeWidgetItem *keyItem = nullptr;
        for (int i = 0; i < rootItem->childCount(); i++) {
            if (rootItem->child(i)->text(0) == name) {
                keyItem = rootItem->child(i);
                break;
            }
        }

        if (!keyItem) {
            keyItem = new QTreeWidgetItem(rootItem);
            keyItem->setText(0, name);
        }

        QTreeWidgetItem *item = new QTreeWidgetItem(keyItem);
        QString cleanPath = cleanFilePath(expandEnvironmentVariables(filePath));
        QIcon icon = getFileIcon(cleanPath);
        QString description = getFileDescription(cleanPath);
        QString keyDescription = winlogonKeyDescriptions.value(name, "未知键");
        QString signature = verifyDigitalSignature(cleanPath);

        item->setIcon(0, icon);
        item->setText(1, name);
        item->setText(2, filePath);
        item->setToolTip(2, filePath);
        item->setText(3, description);
        item->setToolTip(3, description);
        item->setText(4, keyDescription);
        item->setText(5, signature);
        item->setToolTip(5, signature);
        item->setData(0, Qt::UserRole, location);

        updateSignatureColor(item, signature);
    }

    void openRegistryEditor(const QString &regPath) {
        if (regPath.isEmpty()) return;

        QString cleanPath = regPath;
        while (cleanPath.endsWith('\\')) {
            cleanPath.chop(1);
        }

        HKEY hKey;
        LPCSTR subKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit";
        LPCSTR valueName = "LastKey";

        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0, KEY_WRITE, &hKey);
        if (result == ERROR_SUCCESS) {
            result = RegSetValueExA(hKey, valueName, 0, REG_SZ,
                                    (const BYTE*)cleanPath.toStdString().c_str(),
                                    cleanPath.length() + 1);
            if (result == ERROR_SUCCESS) {
                STARTUPINFOA si;
                PROCESS_INFORMATION pi;

                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);
                ZeroMemory(&pi, sizeof(pi));

                if (CreateProcessA(
                        NULL,
                        "regedit.exe",
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        NULL,
                        &si,
                        &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    showDetailedError("启动注册表编辑器", "regedit.exe", GetLastError());
                }
            } else {
                showDetailedError("设置注册表值", subKey, result);
            }
            RegCloseKey(hKey);
        } else {
            showDetailedError("打开注册表键", subKey, result);
        }
    }

    void openFileLocation(const QString &filePath) {
        if (filePath.isEmpty()) return;

        QString cleanPath = cleanFilePath(expandEnvironmentVariables(filePath));
        QFileInfo fileInfo(cleanPath);

        if (fileInfo.exists()) {
            SHELLEXECUTEINFO sei;
            ZeroMemory(&sei, sizeof(sei));
            sei.cbSize = sizeof(sei);
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb = L"open";
            sei.lpFile = L"explorer.exe";

            QString params = QString("/select,\"%1\"").arg(QDir::toNativeSeparators(fileInfo.absoluteFilePath()));
            sei.lpParameters = params.toStdWString().c_str();
            sei.nShow = SW_SHOWNORMAL;

            if (!ShellExecuteEx(&sei)) {
                QString folderPath = QDir::toNativeSeparators(fileInfo.absolutePath());
                QProcess::startDetached("explorer", QStringList() << folderPath);
            }
        } else {
            QMessageBox::warning(this, "错误", "文件不存在: " + cleanPath);
        }
    }

    QTreeWidget* createTree(const QStringList &headers, bool withIcons) {
        QTreeWidget *tree = new QTreeWidget();
        tree->setHeaderLabels(headers);
        tree->setColumnCount(headers.size());
        tree->setSelectionBehavior(QAbstractItemView::SelectRows);
        tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tree->setRootIsDecorated(true);
        tree->setItemsExpandable(true);
        tree->setExpandsOnDoubleClick(true);

        if (headers.size() > 0) tree->setColumnWidth(0, 150);
        if (headers.size() > 1) tree->setColumnWidth(1, 150);
        if (headers.size() > 2) tree->setColumnWidth(2, 300);
        if (headers.size() > 3) tree->setColumnWidth(3, 250);
        if (headers.size() > 4) tree->setColumnWidth(4, 200);
        if (headers.size() > 5) tree->setColumnWidth(5, 200);

        tree->header()->setStretchLastSection(true);

        connect(tree, &QTreeWidget::itemDoubleClicked, this, [=](QTreeWidgetItem *item, int column) {
            if (column == 2) {
                QString filePath = item->text(2);
                if (filePath.isEmpty()) return;

                filePath = expandEnvironmentVariables(filePath);
                QString fileInfo = getFileInfo(filePath);

                QMessageBox::information(this, "文件信息",
                                         QString("文件路径: %1\n\n%2").arg(filePath).arg(fileInfo));
            }
            else {
                onEditItem(tree, item);
            }
        });

        return tree;
    }

    QTableWidget* createTable(const QStringList &headers, bool withIcons) {
        QTableWidget *table = new QTableWidget(0, headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        table->setColumnWidth(0, 30);

        if (headers.size() > 1) table->setColumnWidth(1, 150);
        if (headers.size() > 2) table->setColumnWidth(2, 300);
        if (headers.size() > 3) table->setColumnWidth(3, 250);
        if (headers.size() > 4) table->setColumnWidth(4, 80);
        if (headers.size() > 5) table->setColumnWidth(5, 100);
        if (headers.size() > 6) table->setColumnWidth(6, 200);

        table->horizontalHeader()->setStretchLastSection(true);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);

        connect(table, &QTableWidget::itemDoubleClicked, this, [=](QTableWidgetItem *item) {
            int row = item->row();
            QString filePath = table->item(row, 3)->text();
            if (filePath.isEmpty()) return;

            filePath = expandEnvironmentVariables(filePath);
            QString fileInfo = getFileInfo(filePath);

            QMessageBox::information(this, "文件信息",
                                     QString("文件路径: %1\n\n%2").arg(filePath).arg(fileInfo));
        });

        return table;
    }

    void loadAllStartupsAsync() {
        // 显示进度对话框
        progressDialog->setLabelText("正在加载启动项...");
        progressDialog->setRange(0, 0); // 不确定进度
        progressDialog->show();
        QApplication::processEvents();

        // 清空当前UI
        clearAllUI();

        // 使用QtConcurrent在后台线程加载数据
        QFuture<void> future = QtConcurrent::run([this]() {
            // 加载系统注册表启动项
            loadedData.systemRegistryItems = loadSystemRegistryStartupsData();
            Q_EMIT progressUpdate(20);

            // 加载Wow64注册表启动项
            loadedData.wow64RegistryItems = loadWow64RegistryStartupsData();
            Q_EMIT progressUpdate(40);

            // 加载用户注册表启动项
            loadedData.userRegistryItems = loadUserRegistryStartupsData();
            Q_EMIT progressUpdate(60);

            // 加载Winlogon启动项
            loadedData.winlogonItems = loadWinlogonStartupsData();
            Q_EMIT progressUpdate(70);

            // 加载启动文件夹
            loadedData.startupFolderItems = loadStartupFoldersData();
            Q_EMIT progressUpdate(80);
        });

        // 连接完成信号
        QFutureWatcher<void> *watcher = new QFutureWatcher<void>(this);
        connect(watcher, &QFutureWatcher<void>::finished, this, [this, watcher]() {
            onLoadComplete();
            watcher->deleteLater();
        });
        watcher->setFuture(future);
    }

    void clearAllUI() {
        systemRegistryTree->clear();
        wow64RegistryTree->clear();
        userRegistryTree->clear();
        winlogonTree->clear();
        startupFoldersTree->clear();
    }

    void updateUIWithLoadedData() {
        // 更新系统注册表树
        for (QTreeWidgetItem *item : loadedData.systemRegistryItems) {
            systemRegistryTree->addTopLevelItem(item);
        }

        // 更新Wow64注册表树
        for (QTreeWidgetItem *item : loadedData.wow64RegistryItems) {
            wow64RegistryTree->addTopLevelItem(item);
        }

        // 更新用户注册表树
        for (QTreeWidgetItem *item : loadedData.userRegistryItems) {
            userRegistryTree->addTopLevelItem(item);
        }

        // 更新Winlogon树
        for (QTreeWidgetItem *item : loadedData.winlogonItems) {
            winlogonTree->addTopLevelItem(item);
        }

        // 更新启动文件夹树
        for (QTreeWidgetItem *item : loadedData.startupFolderItems) {
            startupFoldersTree->addTopLevelItem(item);
        }

        // 展开所有树节点
        expandAllTreeItems(systemRegistryTree);
        expandAllTreeItems(wow64RegistryTree);
        expandAllTreeItems(userRegistryTree);
        expandAllTreeItems(winlogonTree);
        expandAllTreeItems(startupFoldersTree);
    }

    void expandAllTreeItems(QTreeWidget *tree) {
        QTreeWidgetItemIterator it(tree);
        while (*it) {
            (*it)->setExpanded(true);
            ++it;
        }
    }

    QString expandEnvironmentVariables(const QString &path) {
        if (path.isEmpty()) return path;

        QString expanded = path;
        wchar_t expandedPath[MAX_PATH];
        DWORD result = ExpandEnvironmentStringsW(path.toStdWString().c_str(), expandedPath, MAX_PATH);

        if (result > 0 && result <= MAX_PATH) {
            expanded = QString::fromWCharArray(expandedPath);
        } else {
            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            int startPos = 0;
            while ((startPos = expanded.indexOf('%', startPos)) != -1) {
                int endPos = expanded.indexOf('%', startPos + 1);
                if (endPos == -1) break;

                QString varName = expanded.mid(startPos + 1, endPos - startPos - 1);
                QString varValue = env.value(varName);

                if (!varValue.isEmpty()) {
                    expanded.replace(startPos, endPos - startPos + 1, varValue);
                    startPos += varValue.length();
                } else {
                    startPos = endPos + 1;
                }
            }
        }

        return expanded;
    }

    QString cleanFilePath(const QString &filePath) {
        if (filePath.isEmpty()) return filePath;

        QString cleaned = filePath.trimmed();

        // 处理带引号的路径
        if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
            cleaned = cleaned.mid(1, cleaned.length() - 2);
        }

        // 查找命令行参数起始位置
        int paramStart = -1;
        bool inQuotes = false;

        for (int i = 0; i < cleaned.length(); ++i) {
            QChar ch = cleaned[i];

            if (ch == '"') {
                inQuotes = !inQuotes; // 切换引号状态
            }
            else if (!inQuotes && ch == ' ') {
                // 不在引号内的空格可能是参数分隔符
                // 检查空格后是否跟着参数标识符（- 或 /）
                if (i + 1 < cleaned.length()) {
                    QChar next = cleaned[i + 1];
                    if (next == '-' || next == '/') {
                        paramStart = i;
                        break;
                    }
                }
            }
        }

        // 截断参数部分，只保留可执行文件路径
        if (paramStart != -1) {
            cleaned = cleaned.left(paramStart).trimmed();
        }

        // 再次检查是否有残留引号
        if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
            cleaned = cleaned.mid(1, cleaned.length() - 2);
        }

        // 转换为绝对路径（如果文件存在）
        QFileInfo fileInfo(cleaned);
        if (fileInfo.exists()) {
            return fileInfo.absoluteFilePath();
        }

        // 尝试修复常见问题
        if (cleaned.contains(" ") && !cleaned.contains("\"")) {
            // 尝试添加引号后再次检查
            QString quoted = "\"" + cleaned + "\"";
            QFileInfo quotedInfo(quoted);
            if (quotedInfo.exists()) {
                return quotedInfo.absoluteFilePath();
            }
        }

        // 处理简单文件名（不含路径分隔符）
        if (!cleaned.contains('\\') && !cleaned.contains('/') && !cleaned.contains(':')) {
            // 尝试在应用程序所在目录中查找
            QString appDir = QCoreApplication::applicationDirPath();
            QString appPath = QDir::cleanPath(appDir + "/" + cleaned);
            if (QFile::exists(appPath)) {
                return QFileInfo(appPath).absoluteFilePath();
            }

            // 尝试在Windows目录中查找
            wchar_t winDir[MAX_PATH];
            if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
                QString windowsPath = QString::fromWCharArray(winDir);
                QString winPath = QDir::cleanPath(windowsPath + "/" + cleaned);
                if (QFile::exists(winPath)) {
                    return QFileInfo(winPath).absoluteFilePath();
                }
            }

            // 尝试在System32目录中查找
            wchar_t sysDir[MAX_PATH];
            if (GetSystemDirectoryW(sysDir, MAX_PATH) > 0) {
                QString system32Path = QString::fromWCharArray(sysDir);
                QString sysPath = QDir::cleanPath(system32Path + "/" + cleaned);
                if (QFile::exists(sysPath)) {
                    return QFileInfo(sysPath).absoluteFilePath();
                }

                // 尝试在SysWow64目录中查找（32位系统文件）
                QString sysWow64Path = system32Path;
                sysWow64Path.replace("system32", "SysWow64", Qt::CaseInsensitive);
                QString sysWow64File = QDir::cleanPath(sysWow64Path + "/" + cleaned);
                if (QFile::exists(sysWow64File)) {
                    return QFileInfo(sysWow64File).absoluteFilePath();
                }
            }

            // 尝试在PATH环境变量路径中查找
            QString pathEnv = QProcessEnvironment::systemEnvironment().value("PATH");
            QStringList pathDirs = pathEnv.split(';', Qt::SkipEmptyParts);

            // 添加常见系统路径
            pathDirs << "C:\\Windows" << "C:\\Windows\\System32" << "C:\\Windows\\SysWow64";

            for (const QString &dir : pathDirs) {
                if (dir.isEmpty()) continue;

                QString fullPath = QDir::cleanPath(dir + "/" + cleaned);
                if (QFile::exists(fullPath)) {
                    return QFileInfo(fullPath).absoluteFilePath();
                }
            }
        }

        return cleaned;
    }

    QIcon getFileIcon(const QString &filePath) {
        if (filePath.isEmpty()) return QApplication::style()->standardIcon(QStyle::SP_FileIcon);

        // 清理文件路径
        QString cleanPath = cleanFilePath(filePath);

        // 获取文件图标
        SHFILEINFO shfi;
        ZeroMemory(&shfi, sizeof(shfi));

        // 尝试获取文件本身的图标
        DWORD flags = SHGFI_ICON | SHGFI_LARGEICON | SHGFI_USEFILEATTRIBUTES;

        if (SHGetFileInfoW(cleanPath.toStdWString().c_str(),
                           FILE_ATTRIBUTE_NORMAL,
                           &shfi,
                           sizeof(shfi),
                           flags)) {
            QIcon icon(QPixmap::fromImage(QImage::fromHICON(shfi.hIcon)));
            DestroyIcon(shfi.hIcon); // 释放图标资源
            return icon;
        }

        // 如果无法获取文件图标，尝试获取文件扩展名对应的图标
        QString ext = QFileInfo(cleanPath).suffix();
        if (!ext.isEmpty()) {
            QString fileExt = "*." + ext;
            if (SHGetFileInfoW(fileExt.toStdWString().c_str(),
                               FILE_ATTRIBUTE_NORMAL,
                               &shfi,
                               sizeof(shfi),
                               flags)) {
                QIcon icon(QPixmap::fromImage(QImage::fromHICON(shfi.hIcon)));
                DestroyIcon(shfi.hIcon); // 释放图标资源
                return icon;
            }
        }

        // 如果仍然无法获取图标，使用系统默认的应用程序图标
        return QApplication::style()->standardIcon(QStyle::SP_FileIcon);
    }

    QString getFileInfo(const QString &filePath) {
        if (filePath.isEmpty()) return "文件路径为空";

        QString info;
        // 清理文件路径
        QString cleanPath = cleanFilePath(filePath);
        QString expandedPath = expandEnvironmentVariables(cleanPath);

        // 获取文件版本信息
        DWORD handle = 0;
        DWORD size = GetFileVersionInfoSizeW(expandedPath.toStdWString().c_str(), &handle);
        if (size > 0) {
            BYTE *buffer = new BYTE[size];
            if (GetFileVersionInfoW(expandedPath.toStdWString().c_str(), handle, size, buffer)) {
                VS_FIXEDFILEINFO *fileInfo;
                UINT len;
                if (VerQueryValueW(buffer, L"\\", (LPVOID*)&fileInfo, &len)) {
                    DWORD fileVersionMS = fileInfo->dwFileVersionMS;
                    DWORD fileVersionLS = fileInfo->dwFileVersionLS;
                    info += QString("文件版本: %1.%2.%3.%4\n")
                                .arg(HIWORD(fileVersionMS))
                                .arg(LOWORD(fileVersionMS))
                                .arg(HIWORD(fileVersionLS))
                                .arg(LOWORD(fileVersionLS));
                }

                // 获取文件描述
                struct LANGANDCODEPAGE {
                    WORD wLanguage;
                    WORD wCodePage;
                } *lpTranslate;

                UINT cbTranslate;
                if (VerQueryValueW(buffer, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
                    for (UINT i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
                        wchar_t subBlock[256];
                        wsprintfW(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
                                  lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);

                        wchar_t *description = NULL;
                        UINT descLen;
                        if (VerQueryValueW(buffer, subBlock, (LPVOID*)&description, &descLen)) {
                            info += QString("文件描述: %1\n").arg(QString::fromWCharArray(description));
                            break;
                        }
                    }
                }
            }
            delete[] buffer;
        }

        // 获取文件属性
        WIN32_FILE_ATTRIBUTE_DATA fileAttr;
        if (GetFileAttributesExW(expandedPath.toStdWString().c_str(), GetFileExInfoStandard, &fileAttr)) {
            ULARGE_INTEGER fileSize;
            fileSize.LowPart = fileAttr.nFileSizeLow;
            fileSize.HighPart = fileAttr.nFileSizeHigh;

            info += QString("文件大小: %1 MB\n").arg(fileSize.QuadPart / (1024.0 * 1024.0), 0, 'f', 2);

            FILETIME ftCreate, ftAccess, ftWrite;
            SYSTEMTIME stCreate, stWrite;
            FileTimeToSystemTime(&fileAttr.ftCreationTime, &stCreate);
            FileTimeToSystemTime(&fileAttr.ftLastWriteTime, &stWrite);

            info += QString("创建时间: %1-%2-%3 %4:%5:%6\n")
                        .arg(stCreate.wYear).arg(stCreate.wMonth, 2, 10, QLatin1Char('0'))
                        .arg(stCreate.wDay, 2, 10, QLatin1Char('0'))
                        .arg(stCreate.wHour, 2, 10, QLatin1Char('0'))
                        .arg(stCreate.wMinute, 2, 10, QLatin1Char('0'))
                        .arg(stCreate.wSecond, 2, 10, QLatin1Char('0'));

            info += QString("修改时间: %1-%2-%3 %4:%5:%6\n")
                        .arg(stWrite.wYear).arg(stWrite.wMonth, 2, 10, QLatin1Char('0'))
                        .arg(stWrite.wDay, 2, 10, QLatin1Char('0'))
                        .arg(stWrite.wHour, 2, 10, QLatin1Char('0'))
                        .arg(stWrite.wMinute, 2, 10, QLatin1Char('0'))
                        .arg(stWrite.wSecond, 2, 10, QLatin1Char('0'));
        }

        // 添加详细的数字签名信息
        QString signatureDetails = signatureVerifier.getSignatureDetails(expandedPath);
        info += "数字签名信息:\n" + signatureDetails + "\n";

        if (info.isEmpty()) {
            info = "无法获取文件信息";
        }

        return info;
    }

    QString getFileDescription(const QString &filePath) {
        if (filePath.isEmpty()) return "";

        QString cleanPath = cleanFilePath(filePath);

        // 检查文件是否存在
        if (!QFile::exists(cleanPath)) {
            return "文件不存在";
        }

        // 获取文件版本信息
        DWORD handle = 0;
        DWORD size = GetFileVersionInfoSizeW(cleanPath.toStdWString().c_str(), &handle);
        if (size == 0) {
            DWORD error = GetLastError();
            if (error == ERROR_RESOURCE_DATA_NOT_FOUND || error == ERROR_RESOURCE_TYPE_NOT_FOUND) {
                return "无版本信息";
            }
            return "无法获取版本信息";
        }

        BYTE *buffer = new BYTE[size];
        if (!GetFileVersionInfoW(cleanPath.toStdWString().c_str(), handle, size, buffer)) {
            delete[] buffer;
            return "无法读取版本信息";
        }

        QString description;

        // 获取文件描述
        struct LANGANDCODEPAGE {
            WORD wLanguage;
            WORD wCodePage;
        } *lpTranslate;

        UINT cbTranslate;
        if (VerQueryValueW(buffer, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
            for (UINT i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
                wchar_t subBlock[256];
                wsprintfW(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
                          lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);

                wchar_t *desc = NULL;
                UINT descLen;
                if (VerQueryValueW(buffer, subBlock, (LPVOID*)&desc, &descLen)) {
                    description = QString::fromWCharArray(desc);
                    break;
                }
            }
        }

        delete[] buffer;
        return description.isEmpty() ? "无描述信息" : description;
    }





    void showDetailedError(const QString &operation, const QString &target, DWORD errorCode) {
        LPWSTR errorMsg = nullptr;
        DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS;

        DWORD size = FormatMessageW(flags, NULL, errorCode,
                                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                    (LPWSTR)&errorMsg, 0, NULL);

        QString message;
        if (size > 0 && errorMsg) {
            message = QString::fromWCharArray(errorMsg);
            LocalFree(errorMsg);
        } else {
            message = "未知错误";
        }

        QMessageBox::critical(this, "操作失败",
                              QString("操作: %1\n目标: %2\n错误: %3\n错误代码: %4")
                                  .arg(operation)
                                  .arg(target)
                                  .arg(message)
                                  .arg(errorCode));
    }

    bool createShortcut(const QString &shortcutPath, const QString &targetPath) {
        IShellLinkW *psl = NULL;
        HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl);
        if (SUCCEEDED(hr)) {
            psl->SetPath(targetPath.toStdWString().c_str());

            IPersistFile *ppf = NULL;
            hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
            if (SUCCEEDED(hr)) {
                hr = ppf->Save(shortcutPath.toStdWString().c_str(), TRUE);
                ppf->Release();
            }
            psl->Release();
        }
        return SUCCEEDED(hr);
    }

    void searchTree(QTreeWidget *tree, const QString &searchText) {
        if (!tree) return;

        bool hasVisibleItems = false;

        // 递归搜索树的所有项目
        std::function<bool(QTreeWidgetItem*)> searchItems = [&](QTreeWidgetItem *item) {
            bool anyChildVisible = false;

            // 递归搜索子项
            for (int i = 0; i < item->childCount(); i++) {
                if (searchItems(item->child(i))) {
                    anyChildVisible = true;
                }
            }

            // 检查当前项是否匹配
            bool itemMatches = false;
            if (!searchText.isEmpty()) {
                for (int col = 0; col < tree->columnCount(); col++) {
                    if (item->text(col).contains(searchText, Qt::CaseInsensitive)) {
                        itemMatches = true;
                        break;
                    }
                }
            } else {
                itemMatches = true; // 空搜索文本显示所有项
            }

            // 如果当前项或任何子项匹配，则显示该项
            bool shouldBeVisible = itemMatches || anyChildVisible;
            item->setHidden(!shouldBeVisible);

            // 如果该项是顶级项且可见，标记为有可见项
            if (item->parent() == nullptr && shouldBeVisible) {
                hasVisibleItems = true;
            }

            return shouldBeVisible;
        };

        // 搜索所有顶级项
        for (int i = 0; i < tree->topLevelItemCount(); i++) {
            searchItems(tree->topLevelItem(i));
        }

        // 如果没有可见项，显示一条消息
        if (!hasVisibleItems && !searchText.isEmpty()) {
            QTreeWidgetItem *noResultsItem = new QTreeWidgetItem();
            noResultsItem->setText(0, "没有找到匹配的启动项");
            noResultsItem->setTextAlignment(0, Qt::AlignCenter);
            tree->addTopLevelItem(noResultsItem);
        }
    }

    void searchTable(QTableWidget *table, const QString &searchText) {
        if (!table) return;

        bool hasVisibleRows = false;

        for (int row = 0; row < table->rowCount(); row++) {
            bool rowMatches = false;

            if (searchText.isEmpty()) {
                rowMatches = true;
            } else {
                // 检查所有列
                for (int col = 0; col < table->columnCount(); col++) {
                    QTableWidgetItem *item = table->item(row, col);
                    if (item && item->text().contains(searchText, Qt::CaseInsensitive)) {
                        rowMatches = true;
                        break;
                    }
                }
            }

            table->setRowHidden(row, !rowMatches);

            if (rowMatches) {
                hasVisibleRows = true;
            }
        }

        // 如果没有可见行，添加一条消息
        if (!hasVisibleRows && !searchText.isEmpty()) {
            int row = table->rowCount();
            table->insertRow(row);
            QTableWidgetItem *noResultsItem = new QTableWidgetItem("没有找到匹配的启动项");
            noResultsItem->setTextAlignment(Qt::AlignCenter);
            table->setItem(row, 0, noResultsItem);
            table->setSpan(row, 0, 1, table->columnCount());
        }
    }

    void showAllTableRows(QTableWidget *table) {
        if (!table) return;

        // 移除"没有找到匹配项"的行
        for (int row = table->rowCount() - 1; row >= 0; row--) {
            QTableWidgetItem *item = table->item(row, 0);
            if (item && item->text() == "没有找到匹配的启动项") {
                table->removeRow(row);
            } else {
                table->setRowHidden(row, false);
            }
        }
    }

signals:
    void progressUpdate(int value);
};

int main(int argc, char *argv[]) {
    // 初始化COM库
    CoInitialize(NULL);

    QApplication app(argc, argv);
    StartupManager manager;
    manager.show();
    int result = app.exec();

    // 反初始化COM库
    CoUninitialize();

    return result;
}

#include "main.moc"
