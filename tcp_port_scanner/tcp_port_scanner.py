import socket
import argparse
import errno

TEST_IP = "127.0.0.1"
TIMEOUT = .01

service_ports = {
    80: 'HTTP',
    443: 'HTTPS',
    21: 'FTP',
    22: 'FTPS, SSH',
    110: 'POP3',
    996: 'POP3 SSL',
    143: 'IMAP',
    993: 'IMAP SSL',
    25: 'SMTP',
    26: 'SMTP',
    587: 'SMTP SSL',
    3306: 'MySQL',
    2082: 'cPANEL',
    2083: 'cPANEL SSL',
    2086: 'WHM',
    2087: 'WHM SSL',
    2095: 'Webmail',
    2096: 'Webmail SSL',
    2077: 'WebDAV/WebDisk',
    2078: 'WebDAV/WebDisk SSL'
}

# taken from here: https://gist.github.com/betrcode/0248f0fda894013382d7, modified slightly
def test_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)

    error = s.connect_ex((ip, port))
    s.close()

    # I was super confused by what you were asking for because the document said to differentiate between fails, but
    # the description said to only print open ones. Didn't know what to do so this only prints open ones, but here's the
    # logic to do it the other way.
    if error == 0:
        return 'Open'
    # elif error == errno.ECONNREFUSED:
    #     return 'Connection Refused'
    elif error == errno.EHOSTDOWN or error == errno.EHOSTUNREACH:
        return 'Unable to reach host'
    else:
        return 'Connection Refused'


def try_ports(ip, service_ports, start=1, finish=1025):
    comm_ports = {}
    for port in range(start, finish):
        result = test_port(ip,port)
        if result == 'Open':
            out_str = "port " + str(port) + ": " + result
            if port in service_ports.keys():
                out_str += ' ' + service_ports[port]
                comm_ports[port] = out_str
            print(out_str)

    # This part was for summarizing the results of printing the result of trying to connect to each port
    # print('Results for common ports:')
    # for value in comm_ports.values():
    #     print(value)


def get_args():
    parser = argparse.ArgumentParser(description= "TCP port scanner that scans for open ports")
    parser.add_argument('hostname', metavar='hostname', type=str, help='Hostname that you want to scan')
    parser.add_argument('-p', dest='ports', help='Range of ports you want to scan in this format: -p 15:25')
    return vars(parser.parse_args())



args = get_args()

if args['hostname'] is None:
    print("Please provide a host name")
else:
    if args['ports'] is None:
        try_ports(args['hostname'], service_ports)
    else:
        ports = args['ports'].split(':')
        if len(ports) != 2:
            print('Improper format: (Range of ports you want to scan in this format: -p 15:25)')
        else:
            try:
                try_ports(args['hostname'], service_ports, int(ports[0]), int(ports[1])+1)
            except:
                print('Non-integer ports entered: (Range of ports you want to scan in this format: -p 15:25)')

