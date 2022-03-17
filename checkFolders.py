#!/usr/bin/env python3

from ldap3 import Server, Connection, SCHEMA, SUBTREE
from pypsrp.client import Client
import json
import socket
import os
import timeit
import argparse
start = timeit.default_timer()

path = "C:/opt/netScripts/data_checkFolders"

parser = argparse.ArgumentParser(description='Parse objects and attributes from Domain Controllers')
parser.add_argument('-f', '--file', dest='file', help='dc=domain1,dc=com;<WINS_DOMAIN>;<IP_address>;<admin_dn>;<admin_user>;<admin_pass>', default='domain_info')
args = parser.parse_args()
domainsFile = open(args.file)

for line in domainsFile:
    [ldap_base, domain, ldap_ip, admin_dn, admin_user,admin_pass] = str.split(line, ";")
    admin_pass = admin_pass.strip('\n')
    print('Script: checkFolders')
    print('Domain:', ldap_base, '| WINSDomain:', domain, '| IP:', ldap_ip, '| AdminDN:', admin_dn, '| AdminUsername', admin_user,'| Admin Pass:********')

pc_criteria = '(objectClass=computer)'
pc_attributes = ['objectSid', 'name']

fsr = {}
fsr["1179785"] = "Read"
fsr["1179817"] = "ReadAndExecute"
fsr["1180063"] = "Read, Write"
fsr["1180095"] = "ReadAndExecute, Write"
fsr["1245631"] = "ReadAndExecute, Modify, Write"
fsr["2032127"] = "FullControl"
fsr["268435456"] = "FullControl (Sub Only)"
fsr["536870912"] = "GENERIC_EXECUTE"
fsr["1073741824"] = "GENERIC_WRITE"
fsr["2147483648"] = "GENERIC_READ"
fsr["-536805376"] = "Modify, Synchronize"
fsr["-1610612736"] = "ReadAndExecute, Synchronize"

scriptDrives = """Get-WmiObject Win32_LogicalDisk -Filter DriveType=3 | Format-Table -Property DeviceID -HideTableHeaders"""

# LDAP Server & Connection
ldap_server = Server(ldap_ip, get_info=SCHEMA)
ldap_handler = Connection(ldap_server, user=admin_dn, password=admin_pass, check_names=True, auto_bind=True)

# LDAP search operation for USERS
ldap_handler.search(search_base=ldap_base, search_filter=pc_criteria, search_scope=SUBTREE, attributes=pc_attributes)

for entry in ldap_handler.entries:
    pc_name = str(entry['name'])
    try:
        pc_ip = socket.gethostbyname(str(entry['name']))
        client = Client(pc_ip, ssl=False, auth="ntlm", encryption="never", username=admin_user, password=admin_pass, cert_validation="False")
        output, streams, had_errors = client.execute_ps(scriptDrives)
        listDrives = output.split()
    except:
        print("Network Device:", pc_name, "is down...")
        pass
    else:
        update_pc = {}
        foldersACLs = []
        update_pc["objectSid"] = str(entry["objectSid"])
        for drv in listDrives:
            admin = str.replace(drv, ":", "$")
            rdir = "\\\\" + pc_name + "\\" + admin + "\\"
            try:
                dir_list = os.scandir(rdir)
            except:
                print("Drive:", rdir, "Not available")
                pass
            else:
                for drct in dir_list:
                    owner = ""
                    if drct.is_file():
                        continue
                    if drct.is_symlink():
                        continue
                    fname = drct.name
                    t = fname[0]
                    if t == '$':
                        continue
                    if t == '.':
                        continue
                    folderGroup = {}
                    pathDir = drct.path
                    ps_script = """Get-Acl \"""" + pathDir + """\" | Select-Object -Property Owner -ExpandProperty Access """
                    output, streams, had_errors = client.execute_ps(ps_script)
                    raw = output
                    line_stream = str.splitlines(output)

                    accessGroup = []
                    acl = {}
                    flag = 0
                    for line in line_stream:
                        if line == '':
                            continue
                        striped = line.strip(' ')
                        term = str.split(striped, sep=" : ")
                        key = term[0].strip()
                        val = term[1].strip()

                        if key == 'Owner':
                            owner = val

                        if key == 'FileSystemRights':
                            if val.strip('-').isnumeric():
                                acl[key] = fsr[val]
                            else:
                                acl[key] = val

                        if key == 'AccessControlType':
                            acl[key] = val

                        if key == 'IdentityReference':
                            acl[key] = val

                        if key == 'IsInherited':
                            acl[key] = val

                        if key == 'InheritanceFlags':
                            acl[key] = val

                        if key == 'PropagationFlags':
                            flag = 1
                            acl[key] = val

                        if flag == 1:
                            accessGroup.append(acl)
                            acl = {}
                            flag = 0
                    folderGroup["owner"] = owner
                    folderGroup["folder"] = pathDir
                    folderGroup["access"] = accessGroup
                    foldersACLs.append(folderGroup)
                dir_list.close()
        update_pc["foldersACLs"] = foldersACLs
        filename = path + "/pc_" + str(entry['name']) + ".json"
        pc_file = open(filename, 'w', newline='', encoding='utf-8')
        json.dump(update_pc, pc_file)
        print(filename)
        update_pc = {}
        pc_file.close()

# Running time
stop = timeit.default_timer()
total_time = stop - start
mins, secs = divmod(total_time, 60)
hours, mins = divmod(mins, 60)
print("Execution Time... ", f'{round(hours):01}h', f'{round(mins):01}m', f'{round(secs):01}s')

