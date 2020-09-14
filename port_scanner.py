import nmap
import socket
import sys

print("Welcome to my port scanner")
print("<---------------------------------")

print("Choose the input format")
print("\t 1-Host name")
print("\t 2-IP address")
option = input("\t Enter your option: ")

if(option == '1'):
    try:
        hostName = input("Enter the host name: ")
        serverIP = socket.gethostbyname(hostName)
    except socket.gaierror:
        print("Host name could not be resolved")
        sys.exit()
elif(option == '2'):
    serverIP = input("Enter the IP address: ")
else:
    print("Invalid option")
    sys.exit()


scanner = nmap.PortScanner()

def scan(scanner,ip,protocol,scanArgument):
    print("Nmap version",scanner.nmap_version())
    scanner.scan(ip,'1-1024','-v {}'.format(scanArgument))
    print(scanner.scaninfo())
    print("IP status",scanner[ip].state())
    if len(scanner[ip].all_protocols()):
        print("Ports open",scanner[ip][protocol].keys())
    else:
        print("Found no ports open")


print("Choose the scan technique")
print("\t 1-SYN")
print("\t 2-UDP")
print("\t 3-Comprehensive")
scanOption = input("Enter your scan option: ")

if(scanOption == '1'):
    scan(scanner,serverIP,'tcp','-sS')
elif(scanOption == '2'):
    scan(scanner,serverIP,'udp','-sU')
elif(scanOption == '3'):
    scan(scanner,serverIP,'tcp','-sC')
else:
    print("Invalid option")
    sys.exit()

print("Scan finished")