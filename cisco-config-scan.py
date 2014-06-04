#!/usr/bin/env python

import os
import sys
import re

regex_hostname = re.compile(r'\s*hostname (\S+)')
regex_firewall_acl_default_permit = re.compile(r'\s*access-list (\S+) extended permit ip any any')
regex_firewall_interface_pix_shutdown = re.compile(r'\s*interface (\S+) \w+ shutdown')
regex_firewall_interface_pix_active = re.compile(r'\s*interface (\S+) \w+')
regex_firewall_interface_asa = re.compile(r'interface (\S+)')
regex_firewall_interface_alias_pix = re.compile(r'\s*nameif (\S+) (\S+) security\d+')
regex_firewall_interface_alias_asa = re.compile(r'\s+nameif (\S+)')
regex_firewall_interface_no_ip = re.compile(r'\s+no ip address')
regex_firewall_interface_shutdown = re.compile(r'\s+shutdown')
regex_firewall_end_stanza = re.compile(r'!')
regex_firewall_access_group = re.compile(r'\s*access-group (\S+) (in|out) interface (\S+)')
regex_no_password_encryption = re.compile(r'no service password-encryption')
regex_type7_user_password = re.compile(r'username .* password 7')
regex_no_aaa_newmodel = re.compile(r'no aaa new-model')
regex_aaa_authentication_local = re.compile(r'aaa authentication login \S+ local')
regex_http_server = re.compile(r'ip http server')
regex_https_server = re.compile(r'ip http secure-server')
regex_http_acl = re.compile(r'ip http access-class')
regex_snmp_community_no_acl = re.compile(r'snmp-server community \S+ (RO|RW)$')
regex_logging_host = re.compile(r'logging host')
regex_log_login_success = re.compile(r'login on-success log')
regex_log_login_failure = re.compile(r'login on-failure log')
regex_log_terminal_config = re.compile(r'\s+notify syslog')

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
	check_firewall_acl_default_permit = False
	check_firewall_no_interface_acl = False
	check_no_password_encryption = False
	check_no_enhanced_password = False
	check_aaa_disabled = False
	check_aaa_authentication_local = False
	check_unencrypted_http_server = False
	check_no_http_acl = True
	check_no_snmp_acl = False
	check_no_logging_host = True
	check_no_auth_success_logging = True
	check_no_auth_failure_logging = True
	check_no_terminal_config_logging = True
	
	interfaces = dict()
	accessgroups = list()
	appliedacl = list()
	defaultpermitacl = list()
	active_interface = None
	interface_ignore = False

	http_enabled = False
	
	f = open(config)
	
	for line in f:
		
		m = regex_hostname.match(line)
		if m:
			hostname = m.group(1)
			continue
		
		if devicetype == "Firewall":
			check_no_http_acl = False
			check_no_auth_success_logging = False
			check_no_auth_failure_logging = False
			check_no_terminal_config_logging = False

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
				appliedacl.append(m.group(1))
				accessgroups.append(m.group(3))
				continue
			
			m = regex_firewall_acl_default_permit.match(line)
			if m:
				defaultpermitacl.append(m.group(1))
				continue
			
		m = regex_no_password_encryption.match(line)
		if m:
			check_no_password_encryption = True
			continue

		m = regex_type7_user_password.match(line)
		if m:
			check_no_enhanced_password = True
			continue
		
		m = regex_no_aaa_newmodel.match(line)
		if m:
			check_aaa_disabled = True
			continue

		m = regex_aaa_authentication_local.match(line)
		if m:
			check_aaa_authentication_local = True
			continue

		m = regex_logging_host.match(line)
		if m:
			check_no_logging_host = False
			continue

		m = regex_log_login_success.match(line)
		if m:
			check_no_auth_success_logging = False
			continue

		m = regex_log_login_failure.match(line)
		if m:
			check_no_auth_failure_logging = False
			continue

		m = regex_log_terminal_config.match(line)
		if m:
			check_no_terminal_config_logging = False
			continue

		m = regex_snmp_community_no_acl.match(line)
		if m:
			check_no_snmp_acl = True
			continue

		m = regex_http_server.match(line)
		if m:
			http_enabled = True
			check_unencrypted_http_server = True
			continue

		m = regex_https_server.match(line)
		if m:
			http_enabled = True
			continue

		m = regex_http_acl.match(line)
		if m:
			check_no_http_acl = False
			continue
		
	f.close()
	
	if devicetype == "Firewall":
		for i in interfaces.values():
			if i not in accessgroups:
				check_firewall_no_interface_acl = True

		for acl in defaultpermitacl:
			if acl in appliedacl:
				check_firewall_acl_default_permit = True

	return (hostname, devicetype,
			check_firewall_acl_default_permit,
			check_firewall_no_interface_acl,
			check_no_password_encryption,
			check_no_enhanced_password,
			check_aaa_disabled,
			check_aaa_authentication_local,
			check_unencrypted_http_server,
			http_enabled and check_no_http_acl,
			check_no_snmp_acl,
			check_no_logging_host,
			check_no_auth_success_logging or check_no_auth_failure_logging,
			check_no_terminal_config_logging)


for root, dirs, files in os.walk(sys.argv[1]):
    for config in files:
        print analyze_config(os.path.join(root, config))

