import nmap

#main menu
def menu():
    print("\n***************************************************************")
    print('''
 ______     _    _       ______  
|_   _ `.  | |  | |    .' ___  | 
  | | `. \ | |__| |_  / .'   \_| 
  | |  | | |____   _| | |        
 _| |_.' /     _| |_  \ `.___.'\ 
|______.'     |_____|  `.____ .'                                   
          ''')
    print("\n***************************************************************")
    print("By MigueAAM Copyright (c) 2025 all rights reserved")
    while True:
        print(" ==== Port Scanner ==== ")
        print("1. Regular Scan")
        print("2. SYN-ACK Scan")
        print("3. Anonymous Scan")
        print("4. Force Brute Scan")
        print("5. Subnet Scan")
        print("6. Exit")
        print(" ===================== ")
        
        user_option = input("Select an option (1 - 6): ")
        if user_option == '1':
            regular_scan()
        elif user_option == '2':
            syn_scan()
        elif user_option == '3':
            anonymous_scan()
        elif user_option == '4':
            force_brute_scan()
        elif user_option == '5':
            subnet_scan()
        elif user_option == '6':
            print("Thanks for using D4C, Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

# option 1 regular scan
def regular_scan():
    print("=== Regular Scan ===")
    ip_address = input(str("Enter the IP address to scan: "))
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments='-O -sV -sC')
    scanner.all_hosts()
    
    if ip_address in scanner.all_hosts():
        print("Host found!", ip_address, "State:", scanner[ip_address].state())
        for proto in scanner[ip_address].all_protocols():
            print("Protocol:", proto)
            lport = scanner[ip_address][proto].keys()
            for port in sorted(lport):
                print("*******************************************************")
                print("Port:", port, "State:", scanner[ip_address][proto][port]['state'])
                print("Service:", scanner[ip_address][proto][port]['name'])
                print("Product:", scanner[ip_address][proto][port]['product'])
                print("Version:", scanner[ip_address][proto][port]['version'])
    
    else:
        print("Host not found:", ip_address)

# option 2 SYN-ACK Scanning
def syn_scan():
    print("=== SYN-ACK Scan ===")
    ip_address = input(str("Enter the IP address to scan: "))
    scanner_ack = nmap.PortScanner()
    scanner_ack.scan(ip_address, arguments='-v -sS -sV -sC -O')
    
    if ip_address in scanner_ack.all_hosts():
        print("Host found!", ip_address, "State:", scanner_ack[ip_address].state())
        for proto in scanner_ack[ip_address].all_protocols():
            print("Protocol:", proto)
            lport = scanner_ack[ip_address][proto].keys()
            for port in sorted(lport):
                print("*******************************************************")
                print("Port:", port, "State:", scanner_ack[ip_address][proto][port]['state'])
                print("Service:", scanner_ack[ip_address][proto][port]['name'])
                print("Product:", scanner_ack[ip_address][proto][port]['product'])
                print("Version:", scanner_ack[ip_address][proto][port]['version'])
    else:
        print("Host not found:", ip_address)

# option 3 Anonymous Scan
def anonymous_scan():
    print("=== Anonymous Scan ===")
    ip_address = input(str("Enter the IP address to scan: "))
    mac_address = input(str("Enter the MAC address to spoof: "))
    scanner_anonymous = nmap.PortScanner()
    scanner_anonymous.scan(ip_address, arguments='-sS -sV -sC -O --spoof-mac ' + mac_address)
    
    if ip_address in scanner_anonymous.all_hosts():
        print("Host found!", ip_address, "State:", scanner_anonymous[ip_address].state())
        for proto in scanner_anonymous[ip_address].all_protocols():
            print("Protocol:", proto)
            lport = scanner_anonymous[ip_address][proto].keys()
            for port in sorted(lport):
                print("*******************************************************")
                print("Port:", port, "State:", scanner_anonymous[ip_address][proto][port]['state'])
                print("Service:", scanner_anonymous[ip_address][proto][port]['name'])
                print("Product:", scanner_anonymous[ip_address][proto][port]['product'])
                print("Version:", scanner_anonymous[ip_address][proto][port]['version'])
    else:
        print("Host not found:", ip_address)

# option 4 Force Brute Scan
def force_brute_scan():
    print("=== Force Brute Scan ===")
    ip_address = input(str("Enter the IP address to scan: "))
    scanner_brute = nmap.PortScanner()
    scanner_brute.scan(ip_address, arguments= '-sV -sC --min-rate 5000 -n -vvv')
    
    if ip_address in scanner_brute.all_hosts():
        print("Host found!", ip_address, "State:", scanner_brute[ip_address].state())
        for proto in scanner_brute[ip_address].all_protocols():
            print("Protocol:", proto)
            lport = scanner_brute[ip_address][proto].keys()
            for port in sorted(lport):
                print("*******************************************************")
                print("Port:", port, "State:", scanner_brute[ip_address][proto][port]['state'])
                print("Service:", scanner_brute[ip_address][proto][port]['name'])
                print("Product:", scanner_brute[ip_address][proto][port]['product'])
                print("Version:", scanner_brute[ip_address][proto][port]['version'])
    else:
        print("Host not found:", ip_address)

# option 5 subnet scan
def subnet_scan():
    print("=== Subnet Scan ===")
    subnet_network = input(str("Enter the subnet to scan: "))
    scanner_subnet = nmap.PortScanner()
    scanner_subnet.scan(subnet_network, arguments='-n -sP -PE')
    network_list = scanner_subnet.all_hosts()
    for host in network_list:
        print("*******************************************************")
        print("Host found:", host, "State:", scanner_subnet[host].state())
    print("Total hosts found:", len(network_list))
    
#menu function execution
if '_main_' == '_main_':
    menu()
