#!/usr/bin/env python3#import subprocess, sys# p = subprocess.Popen(["powershell.exe",#     #"C:\\Users\\USER\\Desktop\\helloworld.ps1"],#     "C:/opt/netScripts/localGroups.ps1"],#     stdout=sys.stdout)# p.communicate()import argparseimport subprocess as spparser = argparse.ArgumentParser(description='Sample call to PowerShell function from Python')parser.add_argument('--functionToCall', metavar='-f', default='hello', help='Specify function to run')args = parser.parse_args()psResult = sp.Popen([r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe','-ExecutionPolicy','Unrestricted','. ./localGroups.ps1',args.functionToCall],stdout = sp.PIPE,stderr = sp.PIPE)output, error = psResult.communicate()rc = psResult.returncodegroups = str(output, 'utf-8').splitlines()errors = str(error, 'utf-8').splitlines()print(groups)