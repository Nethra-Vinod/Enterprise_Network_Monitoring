from src.analysis.unified_analysis import analyze_all

d = analyze_all()
print('PROTOCOLS', d['protocols'])
print('TCP', d['tcp'])
print('DNS', d['dns'])
print('ARP', d['arp'])
print('ICMP', d['icmp'])
