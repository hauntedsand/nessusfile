"""
nessusfile

Classes for interacting with Nessus scan files. At the moment they only
support reading, not altering. Some fields are not represented on the models.

"""

import ipaddress

from .errors import NoMatchesError
from lxml.etree import parse as parse_xml


class NessusElement(object):

    def __init__(self, element):

        self._element = element

    def xpath(self, expression):

        return self._xpath(expression)

    @property
    def _attributes(self):

        return self._element.attrib
    
    def _query_text(self, path, required=False):

        expression = f'./{path}/text()'
        try:
            return self.xpath(f'./{path}/text()')[0]
        except IndexError:
            if required:
                raise NoMatchesError(
                    f"no matching elements for expression '{expression}'"
                )
            else:
                return None

    def _xpath(self, expression):

        return self._element.xpath(expression)


class NessusReportItem(NessusElement):

    def __repr__(self):

        return f"<NessusReportItem {{plugin_id={self.plugin_id},plugin_name='{self.plugin_name}'}}"

    @property
    def description(self):

        return self._query_text('description')

    @property
    def plugin_family(self):

        return self._attributes['pluginFamily']

    @property
    def plugin_id(self):

        return int(self._attributes['pluginID'])

    @property
    def plugin_name(self):

        return self._attributes['pluginName']

    @property
    def plugin_output(self):

        return self._query_text('plugin_output')

    @property
    def plugin_type(self):

        return self._query_text('plugin_type')

    @property
    def port(self):

        port_attribute = self._attributes['port']
        try:
            return int(port_attribute)
        except:
            raise ValueError(
                f"port '{port_attribute}' is not numeric"
            )

    @property
    def protocol(self):

        return self._attributes['protocol']

    @property
    def service_name(self):

        return self._attributes['svc_name']

    @property
    def severity(self):

        return self._attributes['severity']
    
    @property
    def solution(self):

        return self._query_text('solution')
    
    @property
    def synopsis(self):

        return self._query_text('synopsis')


class NessusHostProperty(NessusElement):

    def __repr__(self):

        return f"<NessusHostProperty {{name='{self.name}',value='{self.value}'}}>"

    @property
    def name(self):

        return self._attributes['name']
    
    @property
    def value(self):

        return self._query_text('.')


class NessusHost(NessusElement):

    def __repr__(self):

        return f"<NessusHost {{name='{self.name}'}}>"

    @property
    def fqdn(self):

        return self.properties['host-fqdn']
    
    @property
    def ip_address(self):

        return ipaddress.ip_address(self.properties['host-ip'])

    @property
    def name(self):

        return self._attributes['name']

    @property
    def properties(self):

        return {property.name: property.value
            for property in self.properties_list}
    
    @property
    def properties_list(self):

        return [
            NessusHostProperty(element)
                for element in self._xpath('./HostProperties/tag')
        ]
    
    @property
    def report_items(self):

        return [
            NessusReportItem(element)
                for element in self._xpath('./ReportItem')
        ]


class NessusScanFile(NessusElement):

    @classmethod
    def load(cls, path):

        return cls(parse_xml(path))

    @property
    def hosts(self):

        return [
            NessusHost(element)
                for element in self._xpath('//Report/ReportHost')
        ]

    def merge_report_items(self):

        report_items_by_plugin_id = {}

        for host in self.hosts:
            for report_item in host.report_items:
                record = report_items_by_plugin_id.setdefault(
                    report_item.plugin_id,
                    {
                        'report_items': []
                    }
                )
                record['report_items'].append((host, report_item))

        # In lieu of the official Nessus plugin database, fetch some basic
        # plugin metadata from the first report item registered with each
        # plugin id

        for record in report_items_by_plugin_id.values():
            record['plugin_name'] = record['report_items'][0][1].plugin_name
        
        return report_items_by_plugin_id

    @property
    def preferences(self):

        preferences = {}

        for preference in self._xpath('/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference'):

            name = preference.xpath('./name/text()')[0].strip()
            try:
                value = preference.xpath('./value/text()')[0].strip()
            except IndexError:
                value = None
            
            preference_values = preferences.setdefault(name, [])
            if value is not None:
                preference_values.append(value)
        
        return preferences

