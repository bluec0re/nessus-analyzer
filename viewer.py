#!/usr/bin/env python2
# encoding: utf-8
import logging
import sys
import traceback
import csv
import os

import sqlalchemy.exc
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker, load_only
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from viewer_gui import Ui_MainWindow
from target_list_gui import Ui_Dialog as Ui_TargetListDialog
from db import NessusReport, NessusHost, NessusVuln, NessusPlugin
from report2db import Base, Session, import_report


row2dict = lambda r: {c: str(getattr(r, c)) for c in r.keys()}


class TargetListDialog(Ui_TargetListDialog, QDialog):
    def __init__(self, parent):
        super(TargetListDialog, self).__init__(parent)

        self.setupUi(self)


class Viewer(Ui_MainWindow, QMainWindow):
    def __init__(self):
        super(Viewer, self).__init__(parent=None)

        self.setupUi(self)

        self.setup_events()

    def setup_events(self):
        self.btn_run_sql.clicked.connect(self.run_sql)
        self.btn_sql_export.clicked.connect(self.export)
#        self.results_tree.itemActivated.connect(self.item_activated)
#        self.results_tree.itemClicked.connect(self.item_activated)
        self.results_tree.currentItemChanged.connect(self.currentitem_changed)
        self.actionOpen.triggered.connect(self.connect_db)
        self.actionCreate.triggered.connect(self.create_db)
        self.actionImport.triggered.connect(self.import_report)
        self.results_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_tree.customContextMenuRequested.connect(self.on_context_menu)

    def run_sql(self):
        sql = self.sql_input.toPlainText()
        with open(os.path.expanduser('~/.nessus-viewer'), 'a') as fp:
            fp.write("{}\n".format(sql.replace('\n', '\t')))
        self.sql_table.clear()

        try:
            results = self.db.execute(sql)
        except sqlalchemy.exc.OperationalError as e:
            self.sql_status.setText(str(e.orig))
            return

        keys = results.keys()

        self.sql_table.setSortingEnabled(True)
        self.sql_table.setColumnCount(len(keys))
        self.sql_table.setHorizontalHeaderLabels(keys)

        rows = results.fetchall()
        self.sql_table.setRowCount(len(rows))
        self.sql_status.setText("{} Results".format(len(rows)))
        for i, row in enumerate(rows):
            for j, c in enumerate(row):
                self.sql_table.setItem(i, j, QTableWidgetItem(str(c)))

        self.sql_table.horizontalHeader().resizeSections(QHeaderView.Stretch)

    def export(self):
        sql = self.sql_input.toPlainText()

        try:
            results = self.db.execute(sql)
        except sqlalchemy.exc.OperationalError as e:
            return

        target = QFileDialog.getSaveFileName(self, "Export Data", "", "*.csv")[0]

        keys = results.keys()
        rows = map(row2dict, results.fetchall())
        with open(target, "w") as fp:
            fp.write("# {}\n".format(sql.replace('\n', ' ')))
            writer = csv.DictWriter(fp, fieldnames=keys)
            writer.writerows(rows)

    def on_context_menu(self, pos):
        item = self.results_tree.itemAt(pos)
        data = item.data(0, Qt.UserRole)
        if not data or data[0] != 'finding':
            return

        menu = QMenu()
        menu.addAction("Show IP:Port list", lambda: self.show_target_list_for_plugin(data[1]))
        menu.addAction("Show IP:Port tree", lambda: self.show_target_tree_for_plugin(data[1]))
        menu.exec_(self.results_tree.viewport().mapToGlobal(pos))

    def show_target_list_for_plugin(self, plugin):
        dialog = TargetListDialog(self)
        targets = set([])
        for vuln in plugin.vulns:
            targets.add("{}:{}".format(vuln.host.ip, vuln.port))
        targets = sorted(list(targets))
        dialog.textBox.setPlainText("\n".join(targets))
        dialog.show()

    def show_target_tree_for_plugin(self, plugin):
        dialog = TargetListDialog(self)
        targets = {}
        for vuln in plugin.vulns:
            if vuln.host.ip not in targets:
                targets[vuln.host.ip] = set([])
            targets[vuln.host.ip].add(vuln.port)
        text = []
        for ip, ports in sorted(targets.items()):
            text.append("{}\n\t{}".format(ip, "\n\t".join(str(p) for p in sorted(ports))))
        dialog.textBox.setPlainText("\n".join(text))
        dialog.show()

    def fill_tree(self):
        self.results_tree.clear()

        reports = QTreeWidgetItem()
        findings = QTreeWidgetItem()
        hosts = QTreeWidgetItem()
        ports = QTreeWidgetItem()
        self.results_tree.addTopLevelItem(reports)
        self.results_tree.addTopLevelItem(findings)
        self.results_tree.addTopLevelItem(hosts)
        self.results_tree.addTopLevelItem(ports)

        cnt = 0
        for report in self.session.query(NessusReport).order_by(NessusReport.name).all():
            item = QTreeWidgetItem()
            item.setText(0, report.name)
            item.setData(0, Qt.UserRole, ('report', report))
            reports.addChild(item)
            cnt += 1
        reports.setText(0, "Reports ({})".format(cnt))

        cnt = 0
        for plugin in self.session.query(NessusPlugin).order_by(NessusPlugin.name).all():
            item = QTreeWidgetItem()
            item.setText(0, plugin.name)
            item.setData(0, Qt.UserRole, ('finding', plugin))
            findings.addChild(item)
            cnt += 1
        findings.setText(0, "Findings ({})".format(cnt))

        cnt = 0
        for host in self.session.query(NessusHost).order_by(NessusHost.name).distinct().all():
            item = QTreeWidgetItem()
            item.setText(0, host.name)
            item.setData(0, Qt.UserRole, ('host', host))
            hosts.addChild(item)
            cnt += 1
        hosts.setText(0, "Hosts ({})".format(cnt))

        cnt = 0
        for port in self.session.query(NessusVuln.port).order_by(NessusVuln.port).distinct().all():
            item = QTreeWidgetItem()
            item.setText(0, str(port.port))
            item.setData(0, Qt.UserRole, ('port', port.port))
            ports.addChild(item)
            cnt += 1
        ports.setText(0, "Ports ({})".format(cnt))

    def item_activated(self, item, column):
        data = item.data(0, Qt.UserRole)
        if not data:
            return

        type, data = data

        if hasattr(self, 'item_{}_activated'.format(type)):
            getattr(self, 'item_{}_activated'.format(type))(item, data)

    def currentitem_changed(self, item, previous):
        data = item.data(0, Qt.UserRole)
        if not data:
            return

        type, data = data

        if hasattr(self, 'item_{}_activated'.format(type)):
            getattr(self, 'item_{}_activated'.format(type))(item, data)

    def item_report_activated(self, item, report):
        items = (
            ('Name', report.name),
            ('Started', report.hosts.value(func.min(NessusHost.started))),
            ('Ended', report.hosts.value(func.max(NessusHost.ended))),
            ('Hosts', report.hosts.count()),
        )

        self.item_table.setRowCount(len(items))
        self.item_table.setColumnCount(2)
        self.item_table.verticalHeader().setVisible(False)
        self.item_table.horizontalHeader().setVisible(False)
        for r, item in enumerate(items):
            for c, v in enumerate(item):
                self.item_table.setItem(r, c, QTableWidgetItem(str(v)))
        self.item_table.horizontalHeader().resizeSections(QHeaderView.Stretch)

    def item_host_activated(self, item, host):
        items = tuple((p.name, p.value) for p in host.properties)
        items += (
            ('Findings', host.vulns.count()),
        )

        self.item_table.setRowCount(len(items))
        self.item_table.setColumnCount(2)
        self.item_table.verticalHeader().setVisible(False)
        self.item_table.horizontalHeader().setVisible(False)
        for r, i in enumerate(items):
            for c, v in enumerate(i):
                self.item_table.setItem(r, c, QTableWidgetItem(str(v)))
        self.item_table.horizontalHeader().resizeSections(QHeaderView.Stretch)

        if not item.childCount():
            ports = QTreeWidgetItem()
            ports.setText(0, 'Ports')
            findings = QTreeWidgetItem()
            findings.setText(0, 'Findings')
            item.addChild(ports)
            item.addChild(findings)

            for pid in host.vulns.distinct('plugin_id').values('plugin_id'):
                pid = pid[0]
                plugin = self.session.query(NessusPlugin).get(pid)
                f = QTreeWidgetItem()
                f.setText(0, plugin.name)
                findings.addChild(f)
                for vuln in host.vulns.filter(NessusVuln.plugin_id==pid).order_by('port'):
                    v = QTreeWidgetItem()
                    v.setText(0, str(vuln.port))
                    f.addChild(v)

            for port in host.vulns.distinct('port').values('port'):
                port = port[0]
                p = QTreeWidgetItem()
                p.setText(0, str(port))
                ports.addChild(p)
                for vuln in host.vulns.filter(NessusVuln.port==port):
                    f = QTreeWidgetItem()
                    f.setText(0, vuln.plugin.name)
                    p.addChild(f)

    def item_port_activated(self, item, port):
        items = (
            ('Hosts', self.session.query(NessusVuln.host_id).filter(NessusVuln.port==port).distinct('host_id').count()),
            ('Findings', self.session.query(NessusVuln.port).filter(NessusVuln.port==port).count()),
        )

        self.item_table.setRowCount(len(items))
        self.item_table.setColumnCount(2)
        self.item_table.verticalHeader().setVisible(False)
        self.item_table.horizontalHeader().setVisible(False)
        for r, i in enumerate(items):
            for c, v in enumerate(i):
                self.item_table.setItem(r, c, QTableWidgetItem(str(v)))
        self.item_table.horizontalHeader().resizeSections(QHeaderView.Stretch)

        if not item.childCount():
            hosts = QTreeWidgetItem()
            hosts.setText(0, 'Hosts')
            findings = QTreeWidgetItem()
            findings.setText(0, 'Findings')
            item.addChild(hosts)
            item.addChild(findings)

            for hid in self.session.query(NessusVuln.host_id).filter(NessusVuln.port==port).distinct('host_id').values('host_id'):
                hid = hid[0]
                host = self.session.query(NessusHost).get(hid)
                h = QTreeWidgetItem()
                h.setText(0, str(host.ip))
                hosts.addChild(h)
                for vuln in self.session.query(NessusVuln).filter(NessusVuln.port==port, NessusVuln.host_id==hid):
                    v = QTreeWidgetItem()
                    v.setText(0, vuln.plugin.name)
                    h.addChild(v)

            for pid in self.session.query(NessusVuln.plugin_id).filter(NessusVuln.port==port).distinct('plugin_id').values('plugin_id'):
                pid = pid[0]
                plugin = self.session.query(NessusPlugin).get(pid)
                f = QTreeWidgetItem()
                f.setText(0, plugin.name)
                findings.addChild(f)
                for vuln in self.session.query(NessusVuln).filter(NessusVuln.port==port, NessusVuln.plugin_id==pid):
                    v = QTreeWidgetItem()
                    v.setText(0, str(vuln.host.ip))
                    f.addChild(v)

    def item_finding_activated(self, item, plugin):
        items = (
            ('Hosts', self.session.query(NessusVuln.host_id).filter(NessusVuln.plugin_id==plugin.id).distinct('host_id').count()),
            ('Ports', plugin.vulns.count()),
        )

        self.item_table.setRowCount(len(items))
        self.item_table.setColumnCount(2)
        self.item_table.verticalHeader().setVisible(False)
        self.item_table.horizontalHeader().setVisible(False)
        for r, i in enumerate(items):
            for c, v in enumerate(i):
                self.item_table.setItem(r, c, QTableWidgetItem(str(v)))
        self.item_table.horizontalHeader().resizeSections(QHeaderView.Stretch)

        if not item.childCount():
            hosts = QTreeWidgetItem()
            hosts.setText(0, 'Hosts')
            ports = QTreeWidgetItem()
            ports.setText(0, 'Ports')
            item.addChild(hosts)
            item.addChild(ports)

            for hid in self.session.query(NessusVuln.host_id).filter(NessusVuln.plugin_id==plugin.id).distinct('host_id').values('host_id'):
                hid = hid[0]
                host = self.session.query(NessusHost).get(hid)
                h = QTreeWidgetItem()
                h.setText(0, str(host.ip))
                hosts.addChild(h)
                for vuln in self.session.query(NessusVuln).filter(NessusVuln.plugin_id==plugin.id, NessusVuln.host_id==hid):
                    v = QTreeWidgetItem()
                    v.setText(0, str(vuln.port))
                    h.addChild(v)

            for port in self.session.query(NessusVuln.port).filter(NessusVuln.plugin_id==plugin.id).distinct('port').values('port'):
                port = port[0]
                p = QTreeWidgetItem()
                p.setText(0, str(port))
                ports.addChild(p)
                for vuln in self.session.query(NessusVuln).filter(NessusVuln.port==port, NessusVuln.plugin_id==plugin.id):
                    v = QTreeWidgetItem()
                    v.setText(0, str(vuln.host.ip))
                    p.addChild(v)

    def connect_db(self):
        target = QFileDialog.getOpenFileName(self, "Open Database", "", "Databases (*.sqlite3 *.db)")[0]
        self.db = create_engine('sqlite:///{}'.format(target))
        self.session = sessionmaker(bind=self.db)()
        self.fill_tree()
        self.actionImport.setEnabled(True)
        self.actionCreate.setEnabled(False)
        self.actionOpen.setEnabled(False)

    def create_db(self):
        target = QFileDialog.getSaveFileName(self, "Create Database", "", "Databases (*.sqlite3 *.db)")[0]
        self.db = create_engine('sqlite:///{}'.format(target))
        self.session = sessionmaker(bind=self.db)()
        Base.metadata.create_all(self.db)
        self.actionImport.setEnabled(True)
        self.actionCreate.setEnabled(False)
        self.actionOpen.setEnabled(False)

    def disconnect_db(self):
        self.db.close()

    def import_report(self):
        Session.configure(bind=self.db)
        target = QFileDialog.getOpenFileName(self, "Import Report", "", "Nessus Report (*.nessus)")[0]
        with open(target, 'r') as fp:
            import_report(fp)
        self.fill_tree()


def hook(type, value, tb):
    traceback.print_exception(type, value, tb)
    sys.exit(1)


if __name__ == '__main__':
    logging.basicConfig(level='INFO')
    sys.excepthook = hook

    app = QApplication(sys.argv)
    viewer = Viewer()
    viewer.show()
    sys.exit(app.exec_())
