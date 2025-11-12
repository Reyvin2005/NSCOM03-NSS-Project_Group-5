from scapy.all import get_if_list

for iface in get_if_list():
    print(iface)