#!/usr/bin/env python2
# encoding: utf-8
import argparse
import locale
import logging
import json
import sys
from datetime import datetime

from helperlib.logging import default_config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
try:
    from libnessus.parser import NessusParser
except ImportError:
    NessusParser = None

from db import NessusHost, NessusReport, NessusPlugin, NessusVuln, TracerouteHop, HostProperty, VulnInfo, Base

Session = sessionmaker()
log = logging.getLogger('report2db')


def connect():
    engine = create_engine('sqlite:///nessus.sqlite3')
    Session.configure(bind=engine)
    Base.metadata.create_all(engine)


def import_report(fileobj):
    if NessusParser is None:
        raise ImportError("Could not find libnessus")

    locale.setlocale(locale.LC_TIME, 'C')
    report = NessusParser.parse_fromstring(fileobj.read())

    session = Session()

    if session.query(NessusReport.id).filter(NessusReport.name==report.name).first():
        log.error("Report %s already exist", report.name)
        return

    dbreport = NessusReport()
    dbreport.name = report.name
    session.add(dbreport)

    for host in report.hosts:
        import_host(session, dbreport, host)

    session.commit()


def import_host(session, dbreport, host):
    if session.query(NessusHost.id).filter(NessusHost.ip==host.ip).first():
        log.warning("Host %s already exist", host.ip)

    dbhost = NessusHost()
    dbhost.credential_scan = host.get_host_property('Credential_Scan') == 'true'
    dbhost.started = datetime.strptime(host.started, '%a %b %d %H:%M:%S %Y')
    dbhost.ended = datetime.strptime(host.ended, '%a %b %d %H:%M:%S %Y')
    dbhost.ip = host.ip
    dbhost.name = host.name
    dbhost.policy = host.get_host_property('policy-used')
    dbhost.report = dbreport
    dbhost.operating_system = host.get_host_property('operating-system')
    dbhost.system_type = host.get_host_property('system-type')
    dbhost.mac_address = host.get_host_property('mac-address')
    dbhost.netbios_name = host.get_host_property('netbios_name')
    dbhost.fqqn = host.get_host_property('host-fqqn')
    session.add(dbhost)

    for name, value in host.get_host_properties.items():
        dbprop = HostProperty()
        dbprop.host = dbhost
        dbprop.name = name
        dbprop.value = json.dumps(value)
        session.add(dbprop)

    i = 0
    while True:
        hop = host.get_host_property('traceroute-hop-{}'.format(i))
        if hop:
            dbhop = TracerouteHop()
            dbhop.host = dbhost
            dbhop.hop = i
            dbhop.ip = hop
            session.add(dbhop)
        else:
            break
        i += 1

    for vuln in host.get_report_items:
        import_vuln(session, dbhost, vuln)


def import_vuln(session, dbhost, vuln):
    plugin = vuln.get_vuln_plugin
    dbplugin = session.query(NessusPlugin).get(plugin['pluginID'])
    if not dbplugin:
        dbplugin = NessusPlugin()
        dbplugin.id = int(plugin['pluginID'])
        dbplugin.name = plugin['pluginName']
        dbplugin.family = plugin['pluginFamily']
        dbplugin.type = plugin['plugin_type']
        dbplugin.description = vuln.description
        session.add(dbplugin)

    dbvuln = NessusVuln()
    dbvuln.host = dbhost
    dbvuln.plugin = dbplugin
    dbvuln.port = int(vuln.port)
    dbvuln.protocol = vuln.protocol
    dbvuln.plugin_output = plugin.get('plugin_output')
    dbvuln.severity = int(vuln.severity)
    dbvuln.sevice = vuln.service
    dbvuln.risk_factor = vuln.get_vuln_risk['risk_factor']
    dbvuln.solution = vuln.solution
    dbvuln.synopsis = vuln.synopsis
    if 'plugin_modification_date' in plugin:
        dbvuln.plugin_modificated = datetime.strptime(plugin['plugin_modification_date'], '%Y/%m/%d')
    if 'plugin_publication_date' in plugin:
        dbvuln.plugin_published = datetime.strptime(plugin['plugin_publication_date'], '%Y/%m/%d')

    session.add(dbvuln)

    for name, value in vuln.get_vuln_info.items():
        dbvi = VulnInfo()
        dbvi.vuln = dbvuln
        dbvi.name = name
        dbvi.value = json.dumps(value)
        session.add(dbvi)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('REPORT', type=argparse.FileType('r'), nargs='+')

    args = parser.parse_args()

    default_config(disable_existing_loggers=False)

    connect()
    for report in args.REPORT:
        log.info(report.name)
        import_report(report)
