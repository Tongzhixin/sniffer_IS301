# -*- coding: utf-8 -*-
import os
import sys

from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QTreeWidget, QFrame, QLineEdit, QPushButton
from PyQt5.QtWidgets import QComboBox, QMenuBar, QAction, QStatusBar, QToolBar, QMenu, QLabel, QGridLayout, QTextBrowser, QSplitter
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from capture_core import *
# 使用matplotlib绘制柱状图
#import numpy as np
#import matplotlib.pyplot as plt
import json
#from monitor_system import start_monitor
#from forged_packet import startForged
from multiprocessing import Process




class SnifferUiWindow(QMainWindow):

    def __init__(self, parent=None):
        super(SnifferUiWindow, self).__init__(parent)
        self.uiInit()

    def uiInit(self):
        self.setWindowTitle("MySniffer")
        self.resize(1920, 1080)

        # 设置图标
        icon_project = QIcon()
        icon_project.addPixmap(
            QPixmap("image/capture.svg"), QIcon.Normal, QIcon.Off)
        self.setWindowIcon(icon_project)
        self.setIconSize(QSize(24, 24))

        self.centralWidget = QWidget(self)
        self.centralWidget.setStyleSheet("background:transparent;")

        # 栅栏布局，使得窗口自适应
        self.gridLayout = QGridLayout(self.centralWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setSpacing(6)

        self.topLayout = QHBoxLayout()
        self.topLayout.setContentsMargins(10, 2, 10, 2)
        self.topLayout.setSpacing(20)

        self.middleLayout = QVBoxLayout()
        self.middleLayout.setContentsMargins = (10, 2, 10, 2)
        self.middleLayout.setSpacing = (6)

        font = QFont()
        #platform = sys.platform
        if platform == 'Windows':
            font.setFamily("Lucida Sans Typewriter")
        if platform == "Linux":
            font.setFamily("Noto Mono")
        font.setPointSize(11)

        self.infoTree = QTreeWidget(self.centralWidget)
        self.infoTree.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.infoTree.setAutoScroll(True)
        self.infoTree.setRootIsDecorated(False)
        self.infoTree.setFont(font)
        # 设置表格为7列
        self.infoTree.setColumnCount(7)
        # 固定行高，取消每次刷新所有行，避免更新数据时不流畅
        self.infoTree.setUniformRowHeights(True)
        # 设置表头
        self.infoTree.headerItem().setText(0, "No.")
        self.infoTree.headerItem().setText(1, "Time")
        self.infoTree.headerItem().setText(2, "Source")
        self.infoTree.headerItem().setText(3, "Destination")
        self.infoTree.headerItem().setText(4, "Protocol")
        self.infoTree.headerItem().setText(5, "Length")
        self.infoTree.headerItem().setText(6, "Info")
        self.infoTree.setStyleSheet("background:transparent;")
        self.infoTree.setSortingEnabled(True)
        self.infoTree.sortItems(0, Qt.AscendingOrder)
        self.infoTree.setColumnWidth(0, 55)
        self.infoTree.setColumnWidth(1, 150)
        self.infoTree.setColumnWidth(2, 180)
        self.infoTree.setColumnWidth(3, 180)
        self.infoTree.setColumnWidth(4, 100)
        self.infoTree.setColumnWidth(5, 70)
        for i in range(7):
            self.infoTree.headerItem().setBackground(i, QBrush(QColor(Qt.white)))
        self.infoTree.setSelectionBehavior(QTreeWidget.SelectRows)
        self.infoTree.setSelectionMode(QTreeWidget.ExtendedSelection)

        self.infoTree.header().setSortIndicatorShown(True)
        self.infoTree.clicked.connect(self.on_tableview_clicked)
        
        self.infoTree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.infoTree.customContextMenuRequested.connect(self.infoTreeItemRight)
        # 数据包详细内容显示框
        self.infoPacket = QTreeWidget(self.centralWidget)
        self.infoPacket.setAutoScroll(True)
        self.infoPacket.setTextElideMode(Qt.ElideMiddle)
        self.infoPacket.header().setStretchLastSection(True)
        self.infoPacket.setStyleSheet("background:transparent; color:white;")
        self.infoPacket.header().hide()
        self.infoPacket.setFont(font)

        # 设为只有一列
        self.infoPacket.setColumnCount(1)
        self.infoPacket.setFrameStyle(QFrame.Box | QFrame.Plain)

        # hex显示区域
        self.infoHex = QTextBrowser(self.centralWidget)
        self.infoHex.setText("")
        self.infoHex.setFont(font)
        self.infoHex.setStyleSheet("background:transparent;  color:white;")
        self.infoHex.setFrameStyle(QFrame.Box | QFrame.Plain)

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.infoTree)
        self.splitter.addWidget(self.infoPacket)
        self.splitter.addWidget(self.infoHex)
        self.middleLayout.addWidget(self.splitter)

        self.gridLayout.addLayout(self.middleLayout, 1, 0, 1, 1)

        self.FilterText = QLineEdit(self.centralWidget)
        self.FilterText.setPlaceholderText("Apply a capture filter … ")
        self.FilterText.setStyleSheet("background:white")
        self.FilterText.setFont(font)
        self.topLayout.addWidget(self.FilterText)

        # 过滤器按钮
        self.FilterButton = QPushButton(self.centralWidget)
        self.FilterButton.setText("过滤")
        iconFilter = QIcon()
        iconFilter.addPixmap(QPixmap("image/filter.png"), QIcon.Normal, QIcon.Off)
        self.FilterButton.setIcon(iconFilter)
        self.FilterButton.setIconSize(QSize(20, 20))
        self.FilterButton.setStyleSheet("background:white")
        self.FilterButton.clicked.connect(self.on_start_action_clicked)
        self.topLayout.addWidget(self.FilterButton)

        # 网卡选择

        self.interfaceChoose = QComboBox(self.centralWidget)
        self.interfaceChoose.setFont(font)
        self.interfaceChoose.setStyleSheet("background:white; color:black;")
        self.topLayout.addWidget(self.interfaceChoose)

        self.topLayout.setStretch(0, 4)
        self.topLayout.setStretch(1, 1)
        self.topLayout.setStretch(2, 4)
        self.gridLayout.addLayout(self.topLayout, 0, 0, 1, 1)
        #keys = []
        row_num = len(keys)
        self.interfaceChoose.addItem("All")
        for i in range(row_num):
            self.interfaceChoose.addItem(keys[i])

        self.setCentralWidget(self.centralWidget)

        self.menuBar = QMenuBar(self)
        self.menuBar.setGeometry(QRect(0, 0, 953, 23))
        self.menuBar.setAccessibleName("")
        self.menuBar.setDefaultUp(True)

        self.menu_F = QMenu(self.menuBar)
        self.menu_F.setTitle("文件(F)")

        self.edit_menu = QMenu(self.menuBar)
        self.edit_menu.setTitle("编辑(E)")

        self.capture_menu = QMenu(self.menuBar)
        self.capture_menu.setTitle("捕获(C)")

        self.menu_H = QMenu(self.menuBar)
        self.menu_H.setTitle("帮助(H)")

        
        self.menu_Statistic = QMenu(self.menuBar)
        self.menu_Statistic.setTitle("统计(S)")
        self.setMenuBar(self.menuBar)

        # 顶部工具栏
        self.mainToolBar = QToolBar(self)
        self.addToolBar(Qt.TopToolBarArea, self.mainToolBar)
        self.statusBar = QStatusBar(self)
        self.mainToolBar.setStyleSheet("background: #EDEDED;")
        self.mainToolBar.setMaximumHeight(40)
        self.setStatusBar(self.statusBar)

        # 字体设置键
        font_set = QAction(self)
        font_set.setText("主窗口字体")
        font_set.triggered.connect(self.on_font_set_clicked)

        # 背景图片设置
        change_border = QAction(self)
        change_border.setText("背景图片")
        change_border.triggered.connect(self.on_change_border_clicked)

        # 开始键
        self.start_action = QAction(self)
        iconStart = QIcon()
        iconStart.addPixmap(QPixmap("image/start.svg"),
                            QIcon.Normal, QIcon.Off)
        self.start_action.setIcon(iconStart)
        self.start_action.setText("开始")
        self.start_action.setShortcut('F1')
        self.start_action.triggered.connect(self.on_start_action_clicked)

        # 停止键
        self.stop_action = QAction(self)
        iconStop = QIcon()
        iconStop.addPixmap(QPixmap("image/stop.png"), QIcon.Normal, QIcon.Off)
        self.stop_action.setIcon(iconStop)
        self.stop_action.setText("停止")
        self.stop_action.setShortcut('F3')
        self.stop_action.setDisabled(True)  # 开始时该按钮不可点击
        self.stop_action.triggered.connect(self.on_stop_action_clicked)

        # 暂停键
        self.pause_action = QAction(self)
        iconPause = QIcon()
        iconPause.addPixmap(QPixmap("image/pause.png"), QIcon.Normal, QIcon.Off)
        self.pause_action.setIcon(iconPause)
        self.pause_action.setText("暂停")
        self.pause_action.setShortcut('F2')
        self.pause_action.setDisabled(True)  # 开始时该按钮不可点击
        self.pause_action.triggered.connect(self.on_pause_action_clicked)

        # 重新开始键
        self.actionRestart = QAction(self)
        iconRestart = QIcon()
        iconRestart.addPixmap(QPixmap("image/restart.png"), QIcon.Normal, QIcon.Off)
        self.actionRestart.setIcon(iconRestart)
        self.actionRestart.setText("重新开始")
        self.actionRestart.setShortcut('F4')
        self.actionRestart.setDisabled(True)  # 开始时该按钮不可点击
        self.actionRestart.triggered.connect(self.on_actionRestart_clicked)

        # 更新数据键
        self.action_update = QAction(self)
        iconUpdate = QIcon()
        iconUpdate.addPixmap(QPixmap("image/update.png"), QIcon.Normal, QIcon.Off)
        self.action_update.setIcon(iconUpdate)
        self.action_update.setText("刷新")
        self.action_update.setShortcut('F5')
        self.action_update.setDisabled(True)
        self.action_update.triggered.connect(
            lambda: self.timer.start(
                flush_time) and self.action_update.setDisabled(True)
        )

        # 帮助文档
        action_readme = QAction(self)
        action_readme.setText("使用文档")
        action_about = QAction(self)
        action_about.setText("关于")
        action_about.triggered.connect(self.on_action_about_clicked)

        # 打开文件键
        action_openfile = QAction(self)
        action_openfile.setText("打开")
        action_openfile.setShortcut("ctrl+O")
        action_openfile.triggered.connect(self.on_action_openfile_clicked)

        # 保存文件键
        action_savefile = QAction(self)
        action_savefile.setText("保存")
        action_savefile.setShortcut("ctrl+S")
        action_savefile.triggered.connect(self.on_action_savefile_clicked)

        # IP地址类型统计图
        self.IP_statistics = QAction(self)
        self.IP_statistics.setText("IP地址类型统计")
        self.IP_statistics.triggered.connect(self.on_IP_statistics_clicked)

        # 报文类型统计图
        self.message_statistics = QAction(self)
        self.message_statistics.setText("报文类型统计")
        self.message_statistics.triggered.connect(
            self.on_message_statistics_clicked)
        """
           添加工具栏：开始，暂停，停止，重新开始
        """
        self.mainToolBar.addAction(self.start_action)
        self.mainToolBar.addAction(self.pause_action)
        self.mainToolBar.addAction(self.stop_action)
        self.mainToolBar.addAction(self.actionRestart)
        self.mainToolBar.addAction(self.action_update)

        self.menu_F.addAction(action_openfile)
        self.menu_F.addAction(action_savefile)
        
        self.menu_F.showFullScreen()

        self.edit_menu.addAction(font_set)
        self.edit_menu.addAction(change_border)

        # 捕获菜单栏添加子菜单
        self.capture_menu.addAction(self.start_action)
        self.capture_menu.addAction(self.pause_action)
        self.capture_menu.addAction(self.stop_action)
        self.capture_menu.addAction(self.actionRestart)

        self.menu_H.addAction(action_readme)
        self.menu_H.addAction(action_about)

        
        self.menu_Statistic.addAction(self.IP_statistics)
        self.menu_Statistic.addAction(self.message_statistics)

        self.menuBar.addAction(self.menu_F.menuAction())
        self.menuBar.addAction(self.edit_menu.menuAction())
        self.menuBar.addAction(self.capture_menu.menuAction())
        
        self.menuBar.addAction(self.menu_Statistic.menuAction())
        self.menuBar.addAction(self.menu_H.menuAction())

        """底部状态栏
            利用self.comNum.setText()实时更新状态栏信息
        """
        self.comNum = QLabel('下载速度：')
        self.baudNum = QLabel('上传速度:')
        self.getSpeed = QLabel('收包速度：')
        self.sendSpeed = QLabel('发包速度：')
        self.netNic = QLabel('Welcome to MySniffer !')
        self.statusBar.setStyleSheet("background: #EDEDED;")
        """各个单元空间占比"""
        self.statusBar.addPermanentWidget(self.netNic, stretch=2)
        self.statusBar.addPermanentWidget(self.getSpeed, stretch=1)
        self.statusBar.addPermanentWidget(self.sendSpeed, stretch=1)
        self.statusBar.addPermanentWidget(self.comNum, stretch=1)
        self.statusBar.addPermanentWidget(self.baudNum, stretch=1)

        QMetaObject.connectSlotsByName(self)
        self.core = Core(self)
        # 设置定时器将抓包列表置底
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.infoTree.scrollToBottom)
        self.show()
        # 触发
    
    def infoTreeItemRight(self, pos):
        try:
            self.contextMenu = QMenu()
            self.actionA = self.contextMenu.addAction("ressemble packet")
            self.actionA.triggered.connect(self.ressemblePacket)
            self.contextMenu.exec_(QCursor.pos())
            #self.contextMenu.show()
        except Exception as e:
            print(e)

    def ressemblePacket(self):
        
        items = self.infoTree.selectedItems()
        idList = []
        for item in items:
            idList.append(item.text(0))
        if len(idList) <=1 :
            QMessageBox.warning(self, "警告", "只选择了一个！")
        else:
            self.timer.stop()
            self.core.on_rightclick_item(idList)
            if not self.core.pause_flag and not self.core.stop_flag:
                self.action_update.setDisabled(False)

    def paintEvent(self, a0: QPaintEvent):
        """
        设置初始背景图片
        """
        with open('tmp.json', 'r') as file_obj:
            '''读取json文件'''
            old_image = json.load(file_obj)
        image = old_image["imageUrl"]
        painter = QPainter(self)
        if image :
            pixmap = QPixmap(image)
        else:
            pixmap = QPixmap('image/background.jpg')
        painter.drawPixmap(self.rect(), pixmap)

    @pyqtSlot()
    def on_tableview_clicked(self):
        """
        展开所选过滤包
        """
        selected_row = self.infoTree.currentItem().text(0)  #当前选择的编号
        #表格停止追踪更新
        if selected_row and selected_row.isdigit():
            self.timer.stop()
            self.show_infoTree((int)(selected_row))
            if not self.core.pause_flag and not self.core.stop_flag:
                self.action_update.setDisabled(False)

    def show_infoTree(self, selected_row):
        """
        清空Frame Information内容
        """
        self.infoPacket.clear()
        """
           添加树节点
           Item1: 第一层树节点
           Item1_1: 第二层树节点，Item1的子节点
           QTreeWidgetItem(parentNode, text)   parentNode:父节点  text：当前节点内容
        """
        parentList, childList, hex_dump = self.core.on_click_item(selected_row)
        p_num = len(parentList)
        for i in range(p_num):
            item1 = QTreeWidgetItem(self.infoPacket)
            item1.setText(0, parentList[i])
            c_num = len(childList[i])
            for j in range(c_num):
                item1_1 = QTreeWidgetItem(item1)
                item1_1.setText(0, childList[i][j])
        self.set_hex_text(hex_dump)

    def get_choose_interface(self):
        """
        设置网卡，分为Linux和Windows
        """
        card = self.interfaceChoose.currentText()
        self.netNic.setText('当前网卡：' + card)
        if (card == 'All'):
            a = None
        elif platform == 'Windows':
            a = netcards[card]
        elif platform == 'Linux':
            a = card
        else:
            a = None
        return a

   
    def set_hex_text(self, text):
        """
        设置hex区文本
        """
        self.infoHex.setText(text)

    about = "作者：Tongzhixin\n\n" + "软件主要功能：\n" + "1. 侦听指定网卡或所有网卡，抓取流经网卡的数据包；\n" \
        + "2. 解析捕获的数据包每层的每个字段，查看数据包的详细内容；\n" + "3. 可通过不同的需求设置了BPF过滤器，获取指定地址、端口或协议等相关条件的报文；\n" \
        + "4. 统计ARP、TCP、UDP、ICMP、IPv4、IPv6报文，并画出（未实现）；\n" + "5. 可将抓取到的数据包另存为pcap文件，并能通过打开一个pcap文件对其中的数据包进行解析；\n\n" \
        + "上海交通大学计算机网络作业\n\n" + "部分按钮功能未实现：\n" + "1. 更换字体；\n" + "2. 分析下面两个报文分析；\n" + "3. 帮助文档；"
    @pyqtSlot()
    def on_action_about_clicked(self):
        """
        关于此软件
        """
        QMessageBox.information(self, "关于", self.about)
        pass

    @pyqtSlot()
    def on_action_savefile_clicked(self):
        """
        保存文件
        """
        if self.core.start_flag or self.core.pause_flag:
            QMessageBox.warning(self, "警告", "请停止当前抓包！")
            return
        self.core.save_captured_to_pcap()
        
   
    @pyqtSlot()
    def on_change_border_clicked(self):
        """
        更换图片
        """
        imgName, imgType = QFileDialog.getOpenFileName(
            self, "打开图片", "C:/", "*.jpg;;*.png;;All Files(*)")
        with open('tmp.json', 'r') as file_obj:
            '''读取json文件'''
            old_image = json.load(file_obj)  # 返回列表数据，也支持字典
        old_image["imageUrl"] = imgName
        with open('tmp.json', 'w') as file:
            json.dump(old_image, file)
        #window_pale = QPalette()
        #window_pale.setBrush(self.backgroundRole(), QBrush(QPixmap(imgName)))
        #self.setPalette(window_pale)
        
    @pyqtSlot()
    def on_font_set_clicked(self):
        """
        设置字体，未实现
        """
        pass

    @pyqtSlot()
    def on_IP_statistics_clicked(self):
        """
        IP包的图数据分析
        """
        pass

    @pyqtSlot()
    def on_message_statistics_clicked(self):
        """
        报文分析
        """
        pass

    @pyqtSlot()
    def on_pause_action_clicked(self):
        """
        激活开始、停止、重新开始键、过滤器、网卡选择框
        """
        self.core.pause_capture()
        self.start_action.setEnabled(True)
        self.stop_action.setDisabled(False)
        self.actionRestart.setDisabled(False)
        self.FilterText.setDisabled(True)
        self.FilterButton.setDisabled(True)
        self.interfaceChoose.setDisabled(False)
        self.pause_action.setDisabled(True)
        self.action_update.setDisabled(True)
        self.timer.stop()
        

    @pyqtSlot()
    def on_start_action_clicked(self):
        """
        点击开始后，过滤器不可编辑，开始按钮、网卡选择框全部设为不可选
        激活暂停、停止键、重新开始键
        """
        if self.core.stop_flag:
            # 重新开始清空面板内容
            self.infoTree.clear()
            self.infoPacket.clear()
            self.set_hex_text("")
        self.core.start_capture(self.get_choose_interface(), self.FilterText.text())
        
        self.start_action.setDisabled(True)
        self.FilterText.setEnabled(False)
        self.FilterButton.setEnabled(False)
        self.interfaceChoose.setEnabled(False)
        self.actionRestart.setDisabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.timer.start(flush_time)
        

    @pyqtSlot()
    def on_stop_action_clicked(self):
        """
        激活开始键、重新开始键、过滤器、网卡选择框
        """
        self.core.stop_capture()
        self.stop_action.setDisabled(True)
        self.pause_action.setDisabled(True)
        self.start_action.setEnabled(True)
        self.FilterText.setDisabled(False)
        self.FilterButton.setDisabled(False)
        self.interfaceChoose.setDisabled(False)
        self.action_update.setDisabled(True)
        self.timer.stop()
        

    
    @pyqtSlot()
    def on_actionRestart_clicked(self):
        """
           点击开始后，过滤器不可编辑，开始按钮，网卡选择框全部设为不可选
           激活暂停、停止键、重新开始键
        """
        # 重新开始清空面板内容
        self.timer.stop()
        self.core.restart_capture(self.get_choose_interface(), self.FilterText.text())
        self.infoTree.clear()
        self.infoPacket.clear()
        self.set_hex_text("")
        
        self.actionRestart.setDisabled(False)
        self.start_action.setDisabled(True)
        self.FilterText.setEnabled(False)
        self.FilterButton.setEnabled(False)
        self.interfaceChoose.setEnabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.timer.start(flush_time)
        

    @pyqtSlot()
    def on_action_openfile_clicked(self):
        """
           打开相关文件，打开之前须停止抓包
        """
        if self.core.start_flag or self.core.pause_flag:
            QMessageBox.warning(self, "警告", "请停止当前抓包！")
            return
        self.core.open_pcap_file()
        


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = SnifferUiWindow()
    app.exec()
