#include "FileUnlockDialog.h"
#include <QHeaderView>
#include <QDebug>


FileUnlockDialog::FileUnlockDialog(const QString &filePath, QWidget *parent)
    : QDialog(parent), m_filePath(filePath) {
    setWindowTitle("解除文件占用 - " + QFileInfo(filePath).fileName());
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    resize(800, 500);
    qDebug() << 11;
    setupUI();
    qDebug() << 12;
    refreshProcessList();
    qDebug() << 13;
}

void FileUnlockDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // 文件路径显示
    QLabel *fileLabel = new QLabel("文件路径: " + m_filePath, this);
    fileLabel->setWordWrap(true);
    fileLabel->setStyleSheet("QLabel { padding: 5px; background-color: #f0f0f0; border: 1px solid #ccc; }");
    mainLayout->addWidget(fileLabel);

    // 状态标签
    m_statusLabel = new QLabel("就绪", this);
    m_statusLabel->setStyleSheet("QLabel { color: #666; padding: 2px; }");
    mainLayout->addWidget(m_statusLabel);

    // 进程表格
    m_processTable = new QTableWidget(this);
    m_processTable->setColumnCount(6); // 修改为6列
    m_processTable->setHorizontalHeaderLabels({"进程ID", "进程名称", "进程路径", "占用文件", "句柄值", "状态"});
    m_processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_processTable->setSortingEnabled(true);
    m_processTable->horizontalHeader()->setStretchLastSection(true);
    m_processTable->verticalHeader()->setVisible(false);

    // 设置列宽
    m_processTable->setColumnWidth(0, 80);   // 进程ID
    m_processTable->setColumnWidth(1, 150);  // 进程名称
    m_processTable->setColumnWidth(2, 200);  // 进程路径
    m_processTable->setColumnWidth(3, 200);  // 占用文件
    m_processTable->setColumnWidth(4, 100);  // 句柄值
    m_processTable->setColumnWidth(5, 100);  // 状态

    mainLayout->addWidget(m_processTable);
    mainLayout->addWidget(m_processTable);

    // 按钮组
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    m_refreshBtn = new QPushButton("刷新", this);
    m_closeHandleBtn = new QPushButton("关闭选中句柄", this);
    m_killProcessBtn = new QPushButton("结束选中进程", this);
    m_unlockAllBtn = new QPushButton("解锁所有句柄", this);
    m_closeBtn = new QPushButton("关闭", this);

    // 设置按钮样式
    QString buttonStyle = "QPushButton { padding: 5px 10px; min-width: 80px; }";
    m_refreshBtn->setStyleSheet(buttonStyle);
    m_closeHandleBtn->setStyleSheet(buttonStyle);
    m_killProcessBtn->setStyleSheet(buttonStyle);
    m_unlockAllBtn->setStyleSheet(buttonStyle);
    m_closeBtn->setStyleSheet(buttonStyle);

    buttonLayout->addWidget(m_refreshBtn);
    buttonLayout->addWidget(m_closeHandleBtn);
    buttonLayout->addWidget(m_killProcessBtn);
    buttonLayout->addWidget(m_unlockAllBtn);
    buttonLayout->addStretch();
    buttonLayout->addWidget(m_closeBtn);

    mainLayout->addLayout(buttonLayout);

    // 连接信号
    connect(m_refreshBtn, &QPushButton::clicked, this, &FileUnlockDialog::onRefreshClicked);
    connect(m_closeHandleBtn, &QPushButton::clicked, this, &FileUnlockDialog::onCloseHandleClicked);
    connect(m_killProcessBtn, &QPushButton::clicked, this, &FileUnlockDialog::onKillProcessClicked);
    connect(m_unlockAllBtn, &QPushButton::clicked, this, &FileUnlockDialog::onUnlockAllClicked);
    connect(m_closeBtn, &QPushButton::clicked, this, &FileUnlockDialog::onCloseClicked);

    // 初始禁用操作按钮
    m_closeHandleBtn->setEnabled(false);
    m_killProcessBtn->setEnabled(false);

    // 选中行变化时更新按钮状态
    connect(m_processTable->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, [this]() {
                bool hasSelection = !m_processTable->selectedItems().isEmpty();
                m_closeHandleBtn->setEnabled(hasSelection);
                m_killProcessBtn->setEnabled(hasSelection);
            });

    // 创建右键菜单
    setupContextMenu();

    // 启用右键菜单
    m_processTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_processTable, &QTableWidget::customContextMenuRequested,
            this, &FileUnlockDialog::showProcessTableContextMenu);
}

// FileUnlockDialog.cpp - 替换原有的右键菜单实现

void FileUnlockDialog::setupContextMenu() {
    // 确保菜单对象被正确创建
    m_contextMenu = new QMenu(this);

    // 创建菜单项
    m_openProcessLocationAction = new QAction("在当前资源管理器打开进程位置", this);
    m_openProcessLocationSystemAction = new QAction("在系统资源管理器打开进程位置", this);
    m_openFileLocationAction = new QAction("在当前资源管理器打开被占用文件", this);
    m_openFileLocationSystemAction = new QAction("在系统资源管理器打开被占用文件", this);

    // 添加到菜单
    m_contextMenu->addAction(m_openProcessLocationAction);
    m_contextMenu->addAction(m_openProcessLocationSystemAction);
    m_contextMenu->addSeparator();
    m_contextMenu->addAction(m_openFileLocationAction);
    m_contextMenu->addAction(m_openFileLocationSystemAction);

    // 连接信号槽 - 使用更安全的方式
    connect(m_openProcessLocationAction, &QAction::triggered,
            this, &FileUnlockDialog::openProcessLocation, Qt::QueuedConnection);
    connect(m_openProcessLocationSystemAction, &QAction::triggered,
            this, &FileUnlockDialog::openProcessLocationInSystem, Qt::QueuedConnection);
    connect(m_openFileLocationAction, &QAction::triggered,
            this, &FileUnlockDialog::openFileLocation, Qt::QueuedConnection);
    connect(m_openFileLocationSystemAction, &QAction::triggered,
            this, &FileUnlockDialog::openFileLocationInSystem, Qt::QueuedConnection);
}

void FileUnlockDialog::showProcessTableContextMenu(const QPoint &pos) {
    // 多重安全检查
    if (!m_processTable || !m_contextMenu) {
        qDebug() << "Context menu or table is null";
        return;
    }

    QModelIndex index = m_processTable->indexAt(pos);
    if (!index.isValid()) {
        qDebug() << "Invalid index at context menu";
        return;
    }

    int row = index.row();

    // 检查行号有效性
    if (row < 0 || row >= m_processTable->rowCount()) {
        qDebug() << "Invalid row number:" << row;
        return;
    }

    // 安全获取表格项
    QTableWidgetItem* processPathItem = nullptr;
    QTableWidgetItem* filePathItem = nullptr;

    if (m_processTable->columnCount() > 2) {
        processPathItem = m_processTable->item(row, 2);
    }
    if (m_processTable->columnCount() > 3) {
        filePathItem = m_processTable->item(row, 3);
    }

    if (!processPathItem || !filePathItem) {
        qDebug() << "Table items are null";
        return;
    }

    QString processPath = processPathItem->text();
    QString filePath = filePathItem->text();

    // 设置菜单项可用性
    bool processValid = !processPath.isEmpty() && QFile::exists(processPath);
    bool fileValid = !filePath.isEmpty() && QFile::exists(filePath);

    if (m_openProcessLocationAction)
        m_openProcessLocationAction->setEnabled(processValid);
    if (m_openProcessLocationSystemAction)
        m_openProcessLocationSystemAction->setEnabled(processValid);
    if (m_openFileLocationAction)
        m_openFileLocationAction->setEnabled(fileValid);
    if (m_openFileLocationSystemAction)
        m_openFileLocationSystemAction->setEnabled(fileValid);

    // 安全执行菜单
    if (m_contextMenu) {
        m_contextMenu->exec(m_processTable->viewport()->mapToGlobal(pos));
    }
}
QString FileUnlockDialog::getSelectedProcessPath() {
    auto selectedItems = m_processTable->selectedItems();
    if (selectedItems.isEmpty()) return QString();

    int row = selectedItems.first()->row();
    return m_processTable->item(row, 2)->text();
}

QString FileUnlockDialog::getSelectedFilePath() {
    auto selectedItems = m_processTable->selectedItems();
    if (selectedItems.isEmpty()) return QString();

    int row = selectedItems.first()->row();
    return m_processTable->item(row, 3)->text();
}
void FileUnlockDialog::openProcessLocation() {
    QString processPath = getSelectedProcessPath();
    if (processPath.isEmpty()) {
        QMessageBox::information(this, "提示", "进程路径为空");
        return;
    }

    QString dirPath = QFileInfo(processPath).path();
    emit openInExplorer(dirPath); // 发送信号给主窗口
}

void FileUnlockDialog::openProcessLocationInSystem() {
    QString processPath = getSelectedProcessPath();
    if (processPath.isEmpty()) {
        QMessageBox::information(this, "提示", "进程路径为空");
        return;
    }

    QString dirPath = QFileInfo(processPath).path();
    QDesktopServices::openUrl(QUrl::fromLocalFile(dirPath));
}

void FileUnlockDialog::openFileLocation() {
    QString filePath = getSelectedFilePath();
    if (filePath.isEmpty()) {
        QMessageBox::information(this, "提示", "文件路径为空");
        return;
    }

    QString dirPath = QFileInfo(filePath).path();
    emit openInExplorer(dirPath); // 发送信号给主窗口
}

void FileUnlockDialog::openFileLocationInSystem() {
    QString filePath = getSelectedFilePath();
    if (filePath.isEmpty()) {
        QMessageBox::information(this, "提示", "文件路径为空");
        return;
    }

    QString dirPath = QFileInfo(filePath).path();
    QDesktopServices::openUrl(QUrl::fromLocalFile(dirPath));
}
void FileUnlockDialog::refreshProcessList() {
    // 获取占用文件的进程列表
    m_processes = m_unlocker.getLockingProcesses(m_filePath);
    qDebug() << 14;
    m_processTable->clearContents();
    m_processTable->setRowCount(0);
    qDebug() << 15;
    if (m_processes.isEmpty()) {
        showStatusMessage("没有检测到占用文件的进程");
        return;
    }
    qDebug() << 16;
    for (const ProcessInfo& process : m_processes) {
        int row = m_processTable->rowCount();
        m_processTable->insertRow(row);

        // PID列
        QTableWidgetItem* pidItem = new QTableWidgetItem(QString::number(process.processId));
        // 存储句柄值到UserRole
        pidItem->setData(Qt::UserRole, static_cast<qulonglong>(process.handleValue));
        m_processTable->setItem(row, 0, pidItem);

        // 进程名称列 - 确保不为空
        QString processName = process.processName;
        if (processName.isEmpty()) {
            processName = QString("进程_%1").arg(process.processId);
        }
        m_processTable->setItem(row, 1, new QTableWidgetItem(processName));

        // 进程路径列 - 处理路径显示
        QString displayPath = process.processPath;
        m_processTable->setItem(row, 2, new QTableWidgetItem(displayPath));
        // 存储完整路径到工具提示
        m_processTable->item(row, 2)->setToolTip(process.processPath);

        // 占用文件列
        QString displayFilePath = process.filePath;
        m_processTable->setItem(row, 3, new QTableWidgetItem(displayFilePath));
        m_processTable->item(row, 3)->setToolTip(process.filePath);

        // 句柄值列（十六进制显示）
        QString handleText;
        if (process.handleValue == 0) {
            handleText = "0x0";
        } else {
            handleText = QString("0x%1").arg(static_cast<quintptr>(process.handleValue), 0, 16);
        }
        m_processTable->setItem(row, 4, new QTableWidgetItem(handleText));

        // 状态列
        QString statusText;
        if (process.handleValue == 0) {
            statusText = "占用中";
        } else {
            statusText = "占用中(有句柄)";
        }
        m_processTable->setItem(row, 5, new QTableWidgetItem(statusText));
    }
    qDebug() << 17;
    showStatusMessage(QString("找到%1个占用进程").arg(m_processes.size()));
}

void FileUnlockDialog::onCloseHandleClicked() {
    auto selectedItems = m_processTable->selectedItems();
    if (selectedItems.isEmpty()) {
        QMessageBox::information(this, "提示", "请先选择一个进程");
        return;
    }

    int row = selectedItems.first()->row();
    DWORD pid = m_processTable->item(row, 0)->text().toUInt();
    ULONG_PTR handle = static_cast<ULONG_PTR>(
        m_processTable->item(row, 0)->data(Qt::UserRole).toULongLong());
    QString processName = m_processTable->item(row, 1)->text();
    QString handleText = m_processTable->item(row, 4)->text();

    // 检查是否有有效的句柄值
    if (handle == 0) {
        QMessageBox::information(this, "提示",
                                 QString("进程 %1 (%2) 没有可用的句柄信息\n\n")
                                         .arg(pid).arg(processName) +
                                     "此进程是通过重启管理器检测到的，但内核对象遍历未找到具体的文件句柄。\n"
                                     "您可以选择结束进程来解除文件占用。");
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(
        this, "确认关闭句柄",
        QString("确定要关闭进程 %1 (%2) 的文件句柄吗？\n句柄值: %3")
            .arg(pid).arg(processName).arg(handleText),
        QMessageBox::Yes | QMessageBox::No
        );

    if (reply == QMessageBox::Yes) {
        showStatusMessage("正在关闭句柄...");

        if (m_unlocker.closeSpecificHandle(pid, handle)) {
            // 更新表格状态
            QTableWidgetItem *statusItem = m_processTable->item(row, 5);
            statusItem->setText("句柄已关闭");
            statusItem->setForeground(Qt::darkGreen);

            showStatusMessage("句柄关闭成功");
            QMessageBox::information(this, "成功", "文件句柄已关闭");
        } else {
            showStatusMessage("句柄关闭失败");
            QMessageBox::warning(this, "失败", "无法关闭文件句柄\n" + m_unlocker.getLastError());
        }
    }
}

void FileUnlockDialog::onUnlockAllClicked() {
    if (m_processes.isEmpty()) {
        QMessageBox::information(this, "提示", "没有找到占用文件的进程");
        return;
    }

    // 计算有句柄信息的进程数量
    int handlesCount = 0;
    for (const auto& process : m_processes) {
        if (process.handleValue != 0) {
            handlesCount++;
        }
    }

    if (handlesCount == 0) {
        QMessageBox::information(this, "提示",
                                 "所有占用进程都是通过重启管理器检测到的，没有具体的句柄信息。\n"
                                 "您可以选择结束进程来解除文件占用。");
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(
        this, "确认解锁",
        QString("确定要尝试关闭所有 %1 个占用文件的句柄吗？").arg(handlesCount),
        QMessageBox::Yes | QMessageBox::No
        );

    if (reply == QMessageBox::Yes) {
        showStatusMessage("正在关闭所有句柄...");

        if (m_unlocker.unlockAllHandles(m_processes)) {
            showStatusMessage("句柄关闭成功");
            refreshProcessList(); // 刷新列表查看结果
            QMessageBox::information(this, "成功", m_unlocker.getLastError());
        } else {
            showStatusMessage("句柄关闭失败");
            QMessageBox::warning(this, "失败", m_unlocker.getLastError());
        }
    }
}

void FileUnlockDialog::onKillProcessClicked() {
    auto selectedItems = m_processTable->selectedItems();
    if (selectedItems.isEmpty()) {
        QMessageBox::information(this, "提示", "请先选择一个进程");
        return;
    }

    int row = selectedItems.first()->row();
    DWORD pid = m_processTable->item(row, 0)->text().toUInt();
    QString processName = m_processTable->item(row, 1)->text();

    QMessageBox::StandardButton reply = QMessageBox::question(
        this, "确认结束进程",
        QString("确定要结束进程 %1 (%2) 吗？\n结束进程可能导致数据丢失或系统不稳定。")
            .arg(pid).arg(processName),
        QMessageBox::Yes | QMessageBox::No
        );

    if (reply == QMessageBox::Yes) {
        showStatusMessage("正在结束进程...");

        if (m_unlocker.terminateProcess(pid)) {
            // 更新表格状态
            QTableWidgetItem *statusItem = m_processTable->item(row, 5);
            statusItem->setText("已结束");
            statusItem->setForeground(Qt::darkGreen);

            showStatusMessage("进程结束成功");
            QMessageBox::information(this, "成功", "进程已结束");
        } else {
            showStatusMessage("进程结束失败");
            QMessageBox::warning(this, "失败", "无法结束进程: " + m_unlocker.getLastError());
        }
    }
}

void FileUnlockDialog::onCloseClicked() {
    accept();
}

void FileUnlockDialog::showStatusMessage(const QString &message) {
    m_statusLabel->setText(message);
    m_statusLabel->repaint();
    QApplication::processEvents(); // 确保UI更新
}
void FileUnlockDialog::onRefreshClicked() {
    showStatusMessage("正在刷新...");
    refreshProcessList();
    showStatusMessage("刷新完成");
}
