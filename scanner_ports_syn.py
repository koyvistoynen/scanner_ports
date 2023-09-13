#pip install scapy
from scapy.layers.inet import ICMP, IP, TCP, sr1
import socket
from datetime import datetime

#Получаем текущее время
start = datetime.now()

#Проверяем доступность узла путем отправки icmp-пакета
def icmp_probe(ip):
    icmp_packet = IP(dst=ip) / ICMP()
    resp_packet = sr1(icmp_packet, timeout = 10)
    return resp_packet is not None

#Обходим все порты, отправляя SYN-пакеты
def syn_scan(ip, ports):
    for port in ports:
        #Флаг S - означает SYN-пакет
        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        resp_packet = sr1(syn_packet, timeout = 10)
        if resp_packet is not None:
            if resp_packet.getlayer('TCP').flags & 0x12 != 0:
                print(f"{ip}:{port} is open/{resp_packet.sprintf('%TCP.sport%')}")
ends = datetime.now()

if __name__ == "__main__":
    name = input("Hostname / IP Address: ")
    #Опредеялем IP-адрес
    ip = socket.gethostbyname(name)
    #Указыаем порты для сканирования
    ports = [20, 21, 22, 23, 25, 43, 53, 80, 443, 445, 1080, 3389]
    #Обрабатываем исключения
    try:
        if icmp_probe(ip):
            syn_ack_packet = syn_scan(ip, ports)
            syn_ack_packet.show()
        else:
            print("Failed to send ICMP packet")
    except AttributeError:
        print("Scan completed!")
        print("<Time:{}>".format(ends - start))