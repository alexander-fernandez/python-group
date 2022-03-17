#!/usr/bin/env python3

from ldap3 import Server, Connection, SCHEMA, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
import json
import timeit
import argparse
import datetime

start = timeit.default_timer()
zero = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
path = "C:/opt/netScripts/data_ldapSchema"

parser = argparse.ArgumentParser(description='Parse objects and attributes from Domain Controllers')
parser.add_argument('-f', '--file', dest='file', help='dc=domain1,dc=com;<WINS_DOMAIN>;<IP_address>;<admin_dn>;<admin_user>;<admin_pass>', default='domain_info')
args = parser.parse_args()
domainsFile = open(args.file)

for line in domainsFile:
    [ldap_base, wins_domain, ldap_ip, admin_dn, admin_user,admin_pass] = str.split(line, ";")
    admin_pass = admin_pass.strip('\n')
    print('Script: ldapSchema')
    print('Domain:', ldap_base, '| WINSDomain:', wins_domain, '| IP:', ldap_ip, '| AdminDN:', admin_dn, '| AdminUsername', admin_user,'| Admin Pass:********')
    
group_criteria = '(objectClass=group)'
user_criteria = '(&(objectClass=user)(!(objectClass=computer)))'
pc_criteria = '(objectClass=computer)'

# LDAP Server & Connection
ldap_server = Server(ldap_ip, get_info=SCHEMA)
ldap_handler = Connection(ldap_server, user=admin_dn, password=admin_pass, auto_bind=True)

# LDAP search operation for USERS and Dumping into JSON file
ldap_handler.search(search_base=ldap_base, search_filter=user_criteria, search_scope=SUBTREE, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], get_operational_attributes=True)

entries = ldap_handler.entries
for user in entries:
    user_dict = {}
    user_attr = user.entry_attributes
    for attr in user_attr:
        if user[attr].value == zero:
            user_dict[attr] = 0
            continue
        if type(user[attr].value) is datetime.datetime:
            user_dict[attr] = str(user[attr])
            continue
        if type(user[attr].value) is bytes:
            user_dict[attr] = user[attr].value.decode()
            continue
        if type(user[attr].value) is list:
            if type(user[attr].value[0]) is datetime.datetime:
                dates = []
                for date in user[attr].value:
                    if date == zero:
                        dates.append(str(0))
                        continue
                    dates.append(str(date))
                user_dict[attr] = dates
                continue
        user_dict[attr] = user[attr].value
    filename = path + "/user_" + str(user.sAMAccountName) + ".json"
    user_file = open(filename, 'w', newline='', encoding='utf-8')
    json.dump(user_dict, user_file)
    print(filename)
    user_file.close()

# LDAP operation for GROUP and Dumping into JSON file
ldap_handler.search(search_base=ldap_base, search_filter=group_criteria, search_scope=SUBTREE, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], get_operational_attributes=True)

entries = ldap_handler.entries
for group in entries:
    group_dict = {}
    group_attr = group.entry_attributes
    for attr in group_attr:
        if group[attr].value == zero:
            group_dict[attr] = 0
            continue
        if type(group[attr].value) is datetime.datetime:
            group_dict[attr] = str(group[attr])
            continue
        if type(group[attr].value) is bytes:
            group_dict[attr] = group[attr].value.decode()
            continue
        if type(group[attr].value) is list:
            if type(group[attr].value[0]) is datetime.datetime:
                dates = []
                for date in group[attr].value:
                    if date == zero:
                        dates.append(str(0))
                        continue
                    dates.append(str(date))
                group_dict[attr] = dates
                continue
        group_dict[attr] = group[attr].value
    filename = path + "/group_" + str(group.sAMAccountName) + ".json"
    group_file = open(filename, 'w', newline='', encoding='utf-8')
    json.dump(group_dict, group_file)
    print(filename)
    group_file.close()

# LDAP operation for COMPUTERS and Dumping into JSON file
ldap_handler.search(search_base=ldap_base, search_filter=pc_criteria, search_scope=SUBTREE, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], get_operational_attributes=True)

entries = ldap_handler.entries
for pc in entries:
    pc_dict = {}
    pc_attr = pc.entry_attributes
    for attr in pc_attr:
        if pc[attr].value == zero:
            pc_dict[attr] = 0
            continue
        if type(pc[attr].value) is datetime.datetime:
            pc_dict[attr] = str(pc[attr])
            continue
        if type(pc[attr].value) is bytes:
            pc_dict[attr] = pc[attr].value.decode()
            continue
        if type(pc[attr].value) is list:
            if type(pc[attr].value[0]) is datetime.datetime:
                dates = []
                for date in pc[attr].value:
                    if date == zero:
                        dates.append(str(0))
                        continue
                    dates.append(str(date))
                pc_dict[attr] = dates
                continue
        pc_dict[attr] = pc[attr].value
    filename = path + "/pc_" + str(pc.name) + ".json"
    pc_file = open(filename, 'w', newline='', encoding='utf-8')
    json.dump(pc_dict, pc_file)
    print(filename)
    pc_file.close()

ldap_handler.unbind()

# Running time
stop = timeit.default_timer()
total_time = stop - start
mins, secs = divmod(total_time, 60)
hours, mins = divmod(mins, 60)
print("Execution Time... ", f'{round(hours):01}h', f'{round(mins):01}m', f'{round(secs):01}s')

