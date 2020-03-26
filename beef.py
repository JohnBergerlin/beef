# -*- coding: utf-8 -*-
print('''

 ▄▄▄▄   ▓█████ ▓█████  █████▒
▓█████▄ ▓█   ▀ ▓█   ▀ ▓██   ▒ 
▒██▒ ▄██▒███   ▒███   ▒████ ░ 
▒██░█▀  ▒▓█  ▄ ▒▓█  ▄ ░▓█▒  ░ 
░▓█  ▀█▓░▒████▒░▒████▒░▒█░    
░▒▓███▀▒░░ ▒░ ░░░ ▒░ ░ ▒ ░    
▒░▒   ░  ░ ░  ░ ░ ░  ░ ░      
 ░    ░    ░      ░    ░ ░    
 ░         ░  ░   ░  ░        
      ░                       
      
      ''')

#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

ip_addr = input(">")
type(ip_addr)

resp = input("""\n Type of scan 
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan
                4)Bergz Scan \n""")
print("You have selected option: ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '4':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sU -sV -O -A')
    print(scanner.scaninfo())
    print(scanner[ip_addr].all_hosts())
    print(scanner[ip_addr]['tcp'].keys())
    print(scanner[ip_addr].get_nmap_last_output())
elif resp >= '5':
    print("Please enter a valid option")







