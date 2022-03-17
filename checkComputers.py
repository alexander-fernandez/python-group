#!/usr/bin/env python3

from ldap3 import Server, Connection, SCHEMA, SUBTREE
from pypsrp.client import Client
import json
import socket
import timeit
import argparse
start = timeit.default_timer()

path = "C:/opt/netScripts/data_checkComputers"

parser = argparse.ArgumentParser(description='Parse objects and attributes from Domain Controllers')
parser.add_argument('-f', '--file', dest='file', help='dc=domain1,dc=com;<WINS_DOMAIN>;<IP_address>;<admin_dn>;<admin_user>;<admin_pass>', default='domain_info')
args = parser.parse_args()
domainsFile = open(args.file)

for line in domainsFile:
    [ldap_base, domain, ldap_ip, admin_dn, admin_user,admin_pass] = str.split(line, ";")
    admin_pass = admin_pass.strip('\n')
    print('Script: checkComputers')
    print('Domain:', ldap_base, '| WINSDomain:', domain, '| IP:', ldap_ip, '| AdminDN:', admin_dn, '| AdminUsername', admin_user,'| Admin Pass:********')

user_criteria = '(&(objectClass=user)(!(objectClass=computer)))'
pc_criteria = '(objectClass=computer)'

user_attributes = ['objectSid', 'sAMAccountName']
pc_attributes = ['objectSid', 'name', 'dNSHostName']

# LDAP Server & Connection
ldap_server = Server(ldap_ip, get_info=SCHEMA)
ldap_handler = Connection(ldap_server, user=admin_dn, password=admin_pass, check_names=True, auto_bind=True)

# LDAP search operation for USERS
ldap_handler.search(search_base=ldap_base, search_filter=user_criteria, search_scope=SUBTREE, attributes=user_attributes)
r_users = ldap_handler.entries

# LDAP operation for COMPUTERS
ldap_handler.search(search_base=ldap_base, search_filter=pc_criteria, search_scope=SUBTREE, attributes=pc_attributes)
r_computers = ldap_handler.entries
on_computers = []

ldap_handler.unbind()
scriptForPCs = """foreach ($LocalGroup in Get-LocalGroup) { $LocalGroup.Name }"""

for pc in r_computers:
    update_computer = {}
    update_computer["objectSid"] = str(pc["objectSid"])
    try:
        pc_ip = socket.gethostbyname(str(pc["dNSHostName"]))
        client = Client(pc_ip, ssl=False, auth="ntlm", encryption="never", username=admin_user, password=admin_pass, cert_validation="False")
        output, streams, had_errors = client.execute_ps(scriptForPCs)
        localGroups = output.split('\n')
    except:
        print("Network Device:", str(pc['name']), "is down...")
        continue
    else:
        update_computer["ip_list"] = pc_ip
        update_computer["group_list"] = localGroups
        pc_filenane = path + "/pc_" + str(pc['name']) + ".json"
        computer_file = open(pc_filenane, 'w', newline='', encoding='utf-8')
        json.dump(update_computer, computer_file)
        print(pc_filenane)
        on_computers.append(pc)
        computer_file.close()
for user in r_users:
    update_user = {}
    update_user["objectSid"] = str(user["objectSid"])
    user_target = domain + '\\' + str(user['sAMAccountName'])
    scriptForUsers = """foreach ($LocalGroup in Get-LocalGroup) { if (Get-LocalGroupMember $LocalGroup -Member """ + user_target + """ -ErrorAction SilentlyContinue) { $LocalGroup.Name }}"""
    localGroups = []
    for pc in on_computers:
        try:
            pc_ip = socket.gethostbyname(str(pc["dNSHostName"]))
            client = Client(pc_ip, ssl=False, auth="ntlm", encryption="never", username=admin_user, password=admin_pass, cert_validation="False")
            output, streams, had_errors = client.execute_ps(scriptForUsers)
            groupList = output.split('\n')
        except:
            continue
        else:
            user_data = {}
            user_data["ip"] = str(pc_ip)
            user_data["hostname"] = str(pc["name"])
            user_data["groups"] = groupList
            localGroups.append(user_data)
    update_user["localGroups"] = localGroups
    user_filename = path + "/user_" + str(user['sAMAccountName']) + ".json"
    user_file = open(user_filename, 'w', newline='', encoding='utf-8')
    json.dump(update_user, user_file)
    user_file.close()

# Running time
stop = timeit.default_timer()
total_time = stop - start
mins, secs = divmod(total_time, 60)
hours, mins = divmod(mins, 60)
print("Execution Time... ", f'{round(hours):01}h', f'{round(mins):01}m', f'{round(secs):01}s')
