// FileUnlockDialog.h
#pragma once
#ifndef FILEUNLOCKDIALOG
#define FILEUNLOCKDIALOG
#include <QDialog>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QtWidgets>
#include <QFileSystemModel>
#include <QHeaderView>
#include <QToolBar>
#include <QComboBox>
#include <QLineEdit>
#include <windows.h>
#include "FileUnlocker.h"

class FileUnlockDialog : public QDialog {
    Q_OBJECT
public:
    explicit FileUnlockDialog(const QString &filePath, QWidget *parent = nullptr);

signals:
    void openInExplorer(const QString &path); // 新增信号，用于通知主窗口打开路径

private slots:
    void onRefreshClicked();
    void onCloseHandleClicked();
    void onKillProcessClicked();
    void onUnlockAllClicked();
    void onCloseClicked();
    void showProcessTableContextMenu(const QPoint &pos); // 新增：显示右键菜单
    void openProcessLocation(); // 新增：打开进程位置
    void openFileLocation(); // 新增：打开文件位置
    void openProcessLocationInSystem(); // 新增：在系统资源管理器打开进程位置
    void openFileLocationInSystem(); // 新增：在系统资源管理器打开文件位置

private:
    void setupUI();
    void refreshProcessList();
    void showStatusMessage(const QString &message);
    QString getSelectedProcessPath(); // 新增：获取选中进程的路径
    QString getSelectedFilePath(); // 新增：获取选中文件的路径
    void setupContextMenu();
    QString m_filePath;
    FileUnlocker m_unlocker;
    QVector<ProcessInfo> m_processes;
    QTableWidget *m_processTable;
    QPushButton *m_refreshBtn;
    QPushButton *m_closeHandleBtn;
    QPushButton *m_killProcessBtn;
    QPushButton *m_unlockAllBtn;
    QPushButton *m_closeBtn;
    QLabel *m_statusLabel;

    // 新增右键菜单
    QMenu *m_contextMenu;
    QAction *m_openProcessLocationAction;
    QAction *m_openProcessLocationSystemAction;
    QAction *m_openFileLocationAction;
    QAction *m_openFileLocationSystemAction;
};
#endif
