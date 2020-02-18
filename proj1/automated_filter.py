import subprocess
import json
import pandas as pd


path_to_pcap =r'./minh.pcap'

''' 
use this one if you want to write to an output file as well: 
tshark_out = subprocess.check_output("tshark -r " + path_to_pcap + " -d tcp.port==23322,ssl -T json -e ip.src -e ip.dst -e "
    "ssl.handshake.extensions_server_name -w output_file.pcap", shell=True)
'''

tshark_out = subprocess.check_output("tshark -r " + path_to_pcap + " -d tcp.port==23322,ssl -T json -e ip.src -e ip.dst "
                                     "-e ssl.handshake.extensions_server_name -Y ssl.handshake", shell=True)
packet_dict = json.loads(tshark_out.decode("utf-8"))
packet_ips = [i['_source']['layers'] for i in packet_dict]
packet_set = {}


out_dict = {'Source IP': [],
            'Dest IP': [],
            'Server Name': [],
            'Organization': []}


for packet_ip in packet_ips:
    key = ''
    if 'ip.src' in packet_ip:
        key += packet_ip['ip.src'][0] + ' ' + packet_ip['ip.dst'][0]
        if 'ssl.handshake.extensions_server_name' in packet_ip:
            key += ' ' + packet_ip['ssl.handshake.extensions_server_name'][0]
        else:
            key += ' No server name found'

        if key not in packet_set:
            packet_set[key] = True
            key = key.split()

            out_dict['Source IP'].append(key[0])
            out_dict['Dest IP'].append(key[1])
            out_dict['Server Name'].append(' '.join(key[2:]))
            try:
                whois_out = subprocess.check_output("whois -H " + str(packet_ip['ip.dst'][0]), shell=True).decode("utf-8")
                whois_out = [line for line in whois_out.splitlines() if line.startswith(("Organization:"))]
                out_dict['Organization'].append(' '.join(whois_out[0].split()[1:]))
            except:
                out_dict['Organization'].append('No organization found')

out_df = pd.DataFrame.from_dict(out_dict)
out_df.to_csv('script_out.csv')
