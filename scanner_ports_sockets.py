import socket
from datetime import datetime
import sys

#Записываем время запуска
start = datetime.now()

#Указываем порты для сканирования
ports = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 43: "Whois", 53: "DNS", 80: "Http",
    115: "Sftp", 123: "NTP", 3389: "RDP"
}

host_name = sys.argv[1]
ip = socket.gethostbyname(host_name)

for port in ports:
    cont = socket.socket()
    cont.settimeout(1)
    try:
        cont.connect((ip, port))
    except socket.error:
        pass
    else:
        print(f"{socket.gethostbyname(ip)}:{str(port)} is open/{ports[port]}")
        cont.close()
ends = datetime.now()
print("<Time to scanning:{}>".format(ends - start))
input("Press Enter to the exit...")