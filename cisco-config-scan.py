#!/usr/bin/env python

import os
import sys
import re

regex_hostname = re.compile(r'\s*hostname (\S+)')
regex_firewall_interface_pix_shutdown = re.compile(r'\s*interface (\S+) \w+ shutdown')
regex_firewall_interface_pix_active = re.compile(r'\s*interface (\S+) \w+')
regex_firewall_interface_asa = re.compile(r'interface (\S+)')
regex_firewall_interface_alias_pix = re.compile(r'\s*nameif (\S+) (\S+) security\d+')
regex_firewall_interface_alias_asa = re.compile(r'\s+nameif (\S+)')
regex_firewall_interface_no_ip = re.compile(r'\s+no ip address')
regex_firewall_interface_shutdown = re.compile(r'\s+shutdown')
regex_firewall_end_stanza = re.compile(r'!')
regex_firewall_access_group = re.compile(r'\s*access-group .* interface (\S+)')
regex_password_encryption = re.compile(r'no service password-encryption')
regex_aaa_newmodel = re.compile(r'no aaa new-model')


def get_device_type(config):
    if "ML1000" in config:
        return "ML-Series"
    if "Routers" in config:
        return "Router"
    if "Switches" in config:
        return "Switch"
    if "Firewalls" in config:
        return "Firewall"
    if "WLC" in config:
        return "WLC"
    return "Unknown"


def analyze_config(config):
    hostname = ""
    devicetype = get_device_type(config)
    check_firewall_no_interface_acl = False
    check_no_password_encryption = False
    check_aaa_disabled = False

    interfaces = dict()
    accessgroups = list()
    active_interface = None
    interface_ignore = False

    f = open(config)

    for line in f:

        m = regex_hostname.match(line)
        if m:
            hostname = m.group(1)
            continue

        if devicetype == "Firewall":

            if active_interface:
                m = regex_firewall_interface_alias_asa.match(line)
                if m:
                    interface_alias = m.group(1)
                    continue

                m = regex_firewall_interface_no_ip.match(line)
                if m:
                    interface_ignore = True
                    continue

                m = regex_firewall_interface_shutdown.match(line)
                if m:
                    interface_ignore = True
                    continue

                m = regex_firewall_end_stanza.match(line)
                if m:
                    if not interface_ignore:
                        interfaces[active_interface] = interface_alias
                    active_interface = None
                    interface_alias = None
                    interface_ignore = False
                    continue

            m = regex_firewall_interface_pix_shutdown.match(line)
            if m:
                continue
            else:
                m = regex_firewall_interface_pix_active.match(line)
                if m:
                    interfaces[m.group(1)] = None
                    continue

            m = regex_firewall_interface_alias_pix.match(line)
            if m:
                if m.group(1) in interfaces:
                    interfaces[m.group(1)] = m.group(2)
                continue

            m = regex_firewall_interface_asa.match(line)
            if m:
                active_interface = m.group(1)
                continue

            m = regex_firewall_access_group.match(line)
            if m:
                accessgroups.append(m.group(1))
                continue

        m = regex_password_encryption.match(line)
        if m:
            check_no_password_encryption = True
            continue

        m = regex_aaa_newmodel.match(line)
        if m:
            check_aaa_disabled = True
            continue

    f.close()

    if devicetype == "Firewall":
        for i in interfaces.values():
            if i not in accessgroups:
                check_firewall_no_interface_acl = True

    return (config, hostname, devicetype,
            check_firewall_no_interface_acl,
            check_no_password_encryption,
            check_aaa_disabled)


for root, dirs, files in os.walk(sys.argv[1]):
    for config in files:
        print analyze_config(os.path.join(root, config))

