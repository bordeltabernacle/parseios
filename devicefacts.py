#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Cisco Clerk

Attributes:
    HOSTNAME_REGEX (str):
      Regex to extract the device hostname.

      Matches: HOSTNAME#sh version

      Assumes the `show version` command is used in the `show` command files,
      and the hostname is the name before the # symbol.

    SERIAL_NUMBER_REGEX (str):
      Regex to extract the device serial number.

      Matches: System serial number            : ABC2016XYZ

    MODEL_SW_PATTERN (str):
      Regex to extract device model number, software version and software image.

      Matches: WS-C2960C-8PC-L    15.0(2)SE5            C2960c405-UNIVERSALK9-M
      Matches: WS-C3650-24TD      03.03.03SE        cat3k_caa-universalk9 INSTALL
"""

import os
import re
import json
from collections import namedtuple


class Device:

    def __init__(self, show_file):
        self._source_file = show_file

    def _build_regex(self, regex):
        return re.compile(regex, re.IGNORECASE)

    def _regexes(self):
        return {
            "hn_sh_ver": self._build_regex(r"(?P<hostname>\S+)\#sh[ow\s]+ver.*"),
            "hn_sh_inv": self._build_regex(r"(?P<hostname>\S+)\#sh[ow\s]+inv.*"),
            "hn_sh_run": self._build_regex(r"(?P<hostname>\S+)\#sh[ow\s]+run.*"),
            "hn_hn": self._build_regex(r"hostname\s(?P<hostname>.*)"),
            "mn": self._build_regex(r"model\snumber\s+:\s(?P<model_number>[\w-]+)"),
            "inv_mn": self._build_regex(r"NAME:\s\"[\w\s]*\d\",\sDESCR:\s\"([-\w]+)"),
            "interface": self._build_regex(r"interface\sfastethernet(\d)\/\d"),
            "inv_name": self._build_regex(r"name:\s\"(\d)\""),
            "sn_ssn":
            self._build_regex(
                r"System\sSerial\sNumber\s+:\s(?P<serial_number>\w+)"),
            "sn_sn":
            self._build_regex(
                r"NAME:\s\"(\d|.*\Stack)\",\sDESCR:\s\"[-?\w\s?]+\"\nPID:\s[\w-]+\s+,\sVID:\s\w+\s+,\sSN:\s(?P<serial_number>\w+)"),
            "m_sw":
            self._build_regex(
                r"(?P<model_num>[\w-]+)\s+(?P<sw_ver>\d{2}\.[\w\.)?(?]+)\s+(?P<sw_image>\w+[-|_][\w-]+\-[\w]+)"),
        }

    def _content(self):
        with open(self._source_file) as sf:
            return sf.read()

    def source(self):
        return self._source_file

    def device_count(self):
        interface_slots = re.findall(self._regexes()["interface"],
                self._content())
        inv_names = re.findall(self._regexes()["inv_name"], self._content())
        if interface_slots:
            return int(max(interface_slots)) + 1
        elif inv_names:
            return int(max(inv_names))
        elif self.serial_numbers():
            return len(self.serial_numbers())
        else:
            return None

    def _regex_search(self, key):
        return self._regexes()[key].search(self._content())

    def _regex_finditer(self, key):
        return re.finditer(self._regexes()[key], self._content())

    def _regex_findall(self, key):
        return re.findall(self._regexes()[key], self._content())

    def hostname(self):
        matches = [
            self._regex_search("hn_hn"),
            self._regex_search("hn_sh_ver"),
            self._regex_search("hn_sh_inv"),
            self._regex_search("hn_sh_run"),
        ]
        for match in matches:
            if match:
                return match.group("hostname")
        return None

    def serial_numbers(self):
        matches = [
            self._regex_finditer("sn_sn"),
            self._regex_finditer("sn_ssn"),
        ]
        sn_list = []
        for match in matches:
            if match:
                # Don't use a set, as we need to keep the order the serial
                # numbers are found in so we can accurately match them to
                # the correct device if there is a switch stack
                [sn_list.append(m.group("serial_number")) for m in match if
                        m.group("serial_number") not in sn_list]
                return sn_list
        return None

    def _model_and_software_info(self):
        matches = self._regex_findall("m_sw")
        if matches:
            return matches[:self.device_count()]
        else:
            return None

    def model_numbers(self):
        matches = [
            (i[0] for i in self._model_and_software_info()),
            self._regex_findall("mn"),
            self._regex_findall("inv_mn")
        ]
        for match in matches:
            if match:
                return list(set(match))
        return None

    def software_versions(self):
        svs = [i[1] for i in self._model_and_software_info()]
        if svs:
            return list(set((svs)))
        else:
            return None

    def software_images(self):
        sis = [i[2] for i in self._model_and_software_info()]
        if sis:
            return (list(set(sis)))
        else:
            return None

    def facts(self):
        details_list = []
        Host = namedtuple("Host", "hostname count details")
        Details = namedtuple("Details",
                """serial_number model_number software_version software_image""")
        for i in range(self.device_count()):
            details_list.append(Details(
                self.serial_numbers()[i],
                self._model_and_software_info()[i][0],
                self._model_and_software_info()[i][1],
                self._model_and_software_info()[i][2]))
        return Host(self.hostname(), self.device_count(), tuple(details_list))



def collate(directory):
    """
    Creates a list of named tuples. Each named tuple contains the
    hostname, serial number, model number, software version and
    software image for each device within the `show` files
    within the given directory.

    Args:
        directory (str): Directory containing the Cisco show files

    Returns:
        devices (tuple(Device(str))): tuple of named tuples containing device attributes

    Example:
        >>> collate('./test_data')
        (Device(hostname='elizabeth_cotton', serial_number='ANC1111A1AB', model_number='WS-C2960C-8PC-L', software_version='15.0(2)SE5', software_image='C2960c405-UNIVERSALK9-M'), Device(hostname='howlin_wolf', serial_number='ABC2222A2AB', model_number='WS-C2960C-8PC-L', software_version='15.0(2)SE5', software_image='C2960c405-UNIVERSALK9-M'), Device(hostname='lightning_hopkins', serial_number='ABC3333A33A', model_number='WS-C2960X-48FPD-L', software_version='15.0(2)EX5', software_image='C2960X-UNIVERSALK9-M'), Device(hostname='lightning_hopkins', serial_number='ABC4444A44A', model_number='WS-C2960X-48FPD-L', software_version='15.0(2)EX5', software_image='C2960X-UNIVERSALK9-M'), Device(hostname='lightning_hopkins', serial_number='ABC5555A555', model_number='WS-C2960X-24PD-L', software_version='15.0(2)EX5', software_image='C2960X-UNIVERSALK9-M'), Device(hostname='sister_rosetta_tharpe', serial_number='ABC6666A6AB', model_number='WS-C3650-24TD', software_version='03.03.03SE', software_image='cat3k_caa-universalk9'))
    """
    device_list = []
    Device = namedtuple('Device',
                        '''hostname
                           serial_number
                           model_number
                           software_version
                           software_image''')
    for fin in sorted(os.listdir(directory)):
        with open(os.path.join(directory, fin)) as show_f:
            content = show_f.read()
            hostname = fetch_hostname(content)
            serial_numbers = fetch_serial_nums(content)
            model_sw_result = fetch_model_sw(content)
            i = 0
            while i < len(serial_numbers):
                device_list.append(
                    Device(
                        hostname[0],
                        serial_numbers[i],
                        model_sw_result[i][0],
                        model_sw_result[i][1],
                        model_sw_result[i][2]))
                i += 1
    devices = tuple(device_list)
    return devices


def csv_inventory(collated_records):
    """
    Creates a CSV formatted string containing Cisco device attributes from
    a given list of named tuples.

    Args:
        collated_records (iter(Device(str))): iterable of named tuples.

    Returns:
        output (str): CSV formatted string

    Example:
        >>> csv_inventory(collate('./test_data'))
        'hostname,serial_number,model_number,software_version,software_image\\nelizabeth_cotton,ANC1111A1AB,WS-C2960C-8PC-L,15.0(2)SE5,C2960c405-UNIVERSALK9-M\\nhowlin_wolf,ABC2222A2AB,WS-C2960C-8PC-L,15.0(2)SE5,C2960c405-UNIVERSALK9-M\\nlightning_hopkins,ABC3333A33A,WS-C2960X-48FPD-L,15.0(2)EX5,C2960X-UNIVERSALK9-M\\nlightning_hopkins,ABC4444A44A,WS-C2960X-48FPD-L,15.0(2)EX5,C2960X-UNIVERSALK9-M\\nlightning_hopkins,ABC5555A555,WS-C2960X-24PD-L,15.0(2)EX5,C2960X-UNIVERSALK9-M\\nsister_rosetta_tharpe,ABC6666A6AB,WS-C3650-24TD,03.03.03SE,cat3k_caa-universalk9'
    """
    headers = ','.join(list(collated_records[0]._fields))
    rows = [','.join(list(record)) for record in collated_records]
    content = '{0}\n{1}'.format(headers, '\n'.join(rows))
    return content


def json_inventory(collated_records):
    """
    Creates a JSON formatted string containing Cisco device attributes from
    a given list of named tuples.

    Args:
        collated_records (iter(Device(str))): iterable of named tuples.

    Returns:
        output (str): JSON formatted string

    Example:
        >>> json_inventory(collate('./test_data'))
        '[{"software_image": "C2960c405-UNIVERSALK9-M", "serial_number": "ANC1111A1AB", "model_number": "WS-C2960C-8PC-L", "software_version": "15.0(2)SE5", "hostname": "elizabeth_cotton"}, {"software_image": "C2960c405-UNIVERSALK9-M", "serial_number": "ABC2222A2AB", "model_number": "WS-C2960C-8PC-L", "software_version": "15.0(2)SE5", "hostname": "howlin_wolf"}, {"software_image": "C2960X-UNIVERSALK9-M", "serial_number": "ABC3333A33A", "model_number": "WS-C2960X-48FPD-L", "software_version": "15.0(2)EX5", "hostname": "lightning_hopkins"}, {"software_image": "C2960X-UNIVERSALK9-M", "serial_number": "ABC4444A44A", "model_number": "WS-C2960X-48FPD-L", "software_version": "15.0(2)EX5", "hostname": "lightning_hopkins"}, {"software_image": "C2960X-UNIVERSALK9-M", "serial_number": "ABC5555A555", "model_number": "WS-C2960X-24PD-L", "software_version": "15.0(2)EX5", "hostname": "lightning_hopkins"}, {"software_image": "cat3k_caa-universalk9", "serial_number": "ABC6666A6AB", "model_number": "WS-C3650-24TD", "software_version": "03.03.03SE", "hostname": "sister_rosetta_tharpe"}]'
    """
    dict_records = [__named_tuple_to_dict(record) for record in collated_records]
    return json.dumps(dict_records)

# private function to transform a named tuple into a dictionary
def __named_tuple_to_dict(nt):
    return dict(zip(nt._fields, list(nt)))


def ascii_table_inventory(collated_records):
    """
    Creates an ascii table formatted string containing Cisco device attributes from
    a given list of named tuples.

    Args:
        collated_records (iter(Device(str))): iterable of named tuples.

    Returns:
        output (str): Ascii table formatted string

    Example:
        >>> ascii_table_inventory(collate('./test_data'))

          +-----------------------+---------------+-------------------+-------------------------+------------------+
          | Hostname              | Serial Number | Model Number      | Software Image          | Software Version |
          +-----------------------+---------------+-------------------+-------------------------+------------------+
          | elizabeth_cotton      |  ANC1111A1AB  | WS-C2960C-8PC-L   | C2960c405-UNIVERSALK9-M |    15.0(2)SE5    |
          | howlin_wolf           |  ABC2222A2AB  | WS-C2960C-8PC-L   | C2960c405-UNIVERSALK9-M |    15.0(2)SE5    |
          | lightning_hopkins     |  ABC3333A33A  | WS-C2960X-48FPD-L | C2960X-UNIVERSALK9-M    |    15.0(2)EX5    |
          | lightning_hopkins     |  ABC4444A44A  | WS-C2960X-48FPD-L | C2960X-UNIVERSALK9-M    |    15.0(2)EX5    |
          | lightning_hopkins     |  ABC5555A555  | WS-C2960X-24PD-L  | C2960X-UNIVERSALK9-M    |    15.0(2)EX5    |
          | sister_rosetta_tharpe |  ABC6666A6AB  | WS-C3650-24TD     | cat3k_caa-universalk9   |    03.03.03SE    |
          +-----------------------+---------------+-------------------+-------------------------+------------------+

    """
    hn_col = __width_of_column(collated_records, "hostname", 8)
    sn_col = __width_of_column(collated_records, "serial_number", 13)
    mn_col = __width_of_column(collated_records, "model_number", 12)
    si_col = __width_of_column(collated_records, "software_image", 14)
    sv_col = __width_of_column(collated_records, "software_version", 16)
    table_structure = " | {0:<{hn_col}} | {1:^{sn_col}} | {2:<{mn_col}} | {3:<{si_col}} | {4:^{sv_col}} |"
    table_divider = " +-{0:-^{hn_col}}-+-{1:-^{sn_col}}-+-{2:-^{mn_col}}-+-{3:-^{si_col}}-+-{4:-^{sv_col}}-+".format(
        "", "", "", "", "", hn_col=hn_col, sn_col=sn_col, mn_col=mn_col, si_col=si_col, sv_col=sv_col)
    output = '\n'
    output += table_divider
    output += '\n'

    output += table_structure.format(
        "Hostname",
        "Serial Number",
        "Model Number",
        "Software Image",
        "Software Version",
        hn_col=hn_col,
        sn_col=sn_col,
        mn_col=mn_col,
        si_col=si_col,
        sv_col=sv_col)

    output += '\n'
    output += table_divider
    output += '\n'

    for entry in collated_records:
        output += table_structure.format(
            entry.hostname,
            entry.serial_number,
            entry.model_number,
            entry.software_image,
            entry.software_version,
            hn_col=hn_col,
            sn_col=sn_col,
            mn_col=mn_col,
            si_col=si_col,
            sv_col=sv_col)
        output += '\n'

    output += table_divider
    output += '\n'
    return output

# private function to work out the max width of each table column
def __width_of_column(collated_records, column, init_length):
    for entry in collated_records:
        col_length = len(getattr(entry, column))
        if col_length > init_length:
            init_length = col_length
    return init_length
