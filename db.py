from sqlalchemy import *
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import IPAddressType

Base = declarative_base()


class NessusReport(Base):
    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True)
    name = Column(String, index=True, nullable=False)


class NessusHost(Base):
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey(NessusReport.id), index=True, nullable=False)
    name = Column(String, nullable=False)
    ip = Column(IPAddressType, index=True, nullable=False)
    credential_scan = Column(Boolean)
    started = Column(DateTime)
    ended = Column(DateTime)
    policy = Column(String)
    operating_system = Column(String)
    mac_address = Column(String)
    netbios_name = Column(String)
    fqqn = Column(String)
    system_type = Column(String)

    report = relationship(NessusReport, backref=backref('hosts', order_by=ip, lazy='dynamic'))


class Property(object):
    id = Column(Integer, primary_key=True)
    name = Column(String, index=True, nullable=False)
    value = Column(String)


class HostProperty(Property, Base):
    __tablename__ = 'host_properties'

    host_id = Column(Integer, ForeignKey(NessusHost.id), index=True, nullable=False)

    host = relationship(NessusHost, backref=backref('properties', order_by='HostProperty.name', lazy='dynamic'))


class TracerouteHop(Base):
    __tablename__ = 'hops'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey(NessusHost.id), index=True, nullable=False)
    hop = Column(Integer, nullable=False)
    ip = Column(IPAddressType, nullable=False)

    host = relationship(NessusHost, backref=backref('hops', order_by=hop))


class NessusPlugin(Base):
    __tablename__ = 'plugins'

    id = Column(Integer, primary_key=True)
    name = Column(String, index=True, nullable=False)
    family = Column(String)
    type = Column(String)
    description = Column(String)


class NessusVuln(Base):
    __tablename__ = 'vulns'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey(NessusHost.id), index=True, nullable=False)
    plugin_id = Column(Integer, ForeignKey(NessusPlugin.id), index=True, nullable=False)
    port = Column(Integer, index=True, nullable=False)
    protocol = Column(String, index=True, nullable=False)
    plugin_output = Column(String)
    severity = Column(Integer, index=True, nullable=False)
    service = Column(String)
    risk_factor = Column(String)
    solution = Column(String)
    synopsis = Column(String)
    plugin_modificated = Column(Date)
    plugin_published = Column(Date)

    host = relationship(NessusHost, backref=backref('vulns', lazy='dynamic'))
    plugin = relationship(NessusPlugin, backref=backref('vulns', lazy='dynamic'))


class VulnInfo(Property, Base):
    __tablename__ = 'vuln_infos'

    vuln_id = Column(Integer, ForeignKey(NessusVuln.id), index=True, nullable=False)

    vuln = relationship(NessusVuln, backref=backref('properties', lazy='dynamic'))


class Comment(Base):
    __tablename__ = 'comments'

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey(NessusVuln.id), index=True, nullable=False)
    comment = Column(String, nullable=False)

    vuln = relationship(NessusVuln, backref=backref('comments', lazy='dynamic'))
