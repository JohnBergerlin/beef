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

import sys
import time
import threading
import nmap

scanner = nmap.PortScanner()

ip_addr = input(">")
type(ip_addr)

resp = input(">")

done = False
def animate():
    while done == False:
        sys.stdout.write('\rScanning  |')
        time.sleep(0.1)
        sys.stdout.write('\rsCanning  /')
        time.sleep(0.1)
        sys.stdout.write('\rscAnning  —')
        time.sleep(0.1)
        sys.stdout.write('\rscaNning  \\')
        time.sleep(0.1)
        sys.stdout.write('\rscanNing  |')
        time.sleep(0.1)
        sys.stdout.write('\rscannIng  /')
        time.sleep(0.1)
        sys.stdout.write('\rscanniNg  —')
        time.sleep(0.1)
        sys.stdout.write('\rscanninG  \\')
        time.sleep(0.1)
    sys.stdout.write('\rDone!     ')

t = threading.Thread(target=animate)
t.start()

time.sleep(30)
done = True

if resp == '1':
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print(scanner.scanstats())
elif resp == '2':
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print(scanner.scanstats)
elif resp == '3':
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print(scanner.scanstats())
elif resp == '4':
    scanner.scan(ip_addr, '1-1024', '-v -sS -sU -sV -O -A')
    print(scanner.scaninfo())
    print(scanner.scanstats())
elif resp == '5':
    scanner.scan(ip_addr, '1-1024', '-v -sV -A -O')
    print(scanner.scaninfo())
    print(scanner.scanstats())
elif resp >= '6':
    print("Option Out of Range!")







