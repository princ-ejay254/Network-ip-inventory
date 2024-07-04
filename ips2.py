import nmap

def scan_network(ip_range, output_file):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    with open(output_file, 'w') as f:
        f.write(str(nm.all_hosts()))

def extract_ips(input_file, output_file):
    with open(input_file, 'r') as f:
        data = f.read()
        ips = [line.split()[1] for line in data.splitlines()]
    with open(output_file, 'w') as f:
        f.write('\n'.join(ips))

def main():
    # Define your network IP range
    ip_range = '192.168.1.0/24'
    
    # Scan the network and save the output to a file
    output_file = 'network_scan.txt'
    scan_network(ip_range, output_file)
    print(f"Network scan results saved to {output_file}")
    
    # Extract IP addresses from the output file and save them to another file
    ips_file = 'ips.txt'
    extract_ips(output_file, ips_file)
    print(f"IP addresses extracted and saved to {ips_file}")

if __name__ == "__main__":
    main()

