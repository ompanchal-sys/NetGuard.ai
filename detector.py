from scapy.all import rdpcap,IP,TCP,UDP,DNS,DNSQR
from collections import defaultdict
from datetime import datetime,timezone
import statistics,time,json,math
from ml_model import predict_ml

MIN_PACKETS=20
THRESHOLD=60
THREATS=["SYN Flood","UDP Amplification","Source Flood","C2 Beaconing","DGA / DNS Tunnelling","Encrypted Traffic Anomaly","Port Scanning","Data Exfiltration"]

def packet_time(p):
    try:return float(p.time)
    except:return time.time()

def packet_rate(packets):
    if len(packets)<2:return 0
    t=[packet_time(p) for p in packets];d=max(t)-min(t)
    return len(packets)/d if d>0 else 0

def entropy(text):
    if not text:return 0
    n=len(text)
    return -sum((text.count(c)/n)*math.log2(text.count(c)/n) for c in set(text))

def extract_features(packets):
    sources=defaultdict(int);destinations=defaultdict(int);ports=defaultdict(set)
    flows=defaultdict(lambda:[0,0,[]]);communications=defaultdict(list);dns_queries=[]
    syn=synack=udp=total_bytes=ip_packets=0
    for p in packets:
        if IP not in p:continue
        ip=p[IP];sources[ip.src]+=1;destinations[ip.dst]+=1;total_bytes+=len(p);ip_packets+=1
        if TCP in p:
            tcp=p[TCP];key=(ip.src,ip.dst,tcp.sport,tcp.dport)
            flows[key][0]+=1;flows[key][1]+=len(p);flows[key][2].append(packet_time(p));ports[ip.src].add(tcp.dport)
            flags=int(tcp.flags)
            if flags&2 and not flags&16:syn+=1
            if flags&2 and flags&16:synack+=1
        elif UDP in p:udp+=1
        communications[(ip.src,ip.dst)].append(packet_time(p))
        if DNS in p and DNSQR in p:
            try:
                q=p[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if q:dns_queries.append(q)
            except:pass
    if not ip_packets:return {}
    t=[packet_time(p) for p in packets];duration=max(t)-min(t)
    rate=len(packets)/duration if duration>0 else 0
    dns_len=sum(map(len,dns_queries))/len(dns_queries) if dns_queries else 0
    dns_ent=sum(entropy(x) for x in dns_queries)/len(dns_queries) if dns_queries else 0
    encrypted=sum(v[0]>=20 and v[1]>=30000 and k[3] in (443,8443) for k,v in flows.items())
    large=sum(v[1]>=300000 for v in flows.values())
    regularity=0
    for ts in communications.values():
        if len(ts)<15:continue
        ts.sort();iv=[ts[i]-ts[i-1] for i in range(1,len(ts)) if ts[i]-ts[i-1]>=.5]
        if len(iv)>=10:
            m=statistics.median(iv);r=sum(abs(x-m)<=m*.15 for x in iv)/len(iv)*100
            if ts[-1]-ts[0]>=20:regularity=max(regularity,r)
    return {
        "packet_count":len(packets),"packet_rate":rate,"total_bytes":total_bytes,
        "byte_rate":total_bytes/duration if duration>0 else 0,"duration":duration,
        "syn_count":syn,"syn_rate":syn/duration if duration>0 else 0,
        "synack_ratio":synack/max(syn,1),"udp_count":udp,
        "unique_sources":len(sources),"unique_destinations":len(destinations),
        "max_destination_ports":max((len(x) for x in ports.values()),default=0),
        "dns_count":len(dns_queries),"dns_avg_length":dns_len,
        "dns_avg_entropy":dns_ent,"long_dns_count":sum(len(x)>=45 for x in dns_queries),
        "encrypted_flows":encrypted,"large_flows":large,"beacon_regularity":regularity
    }

def analyze(packets):
    scores={t:0 for t in THREATS}
    if len(packets)<MIN_PACKETS:return "No Threat",0,"Not enough packets for analysis",scores
    sources=defaultdict(int);destinations=defaultdict(int);ports=defaultdict(set)
    flows=defaultdict(lambda:[0,0,[]]);communications=defaultdict(list);dns_queries=[]
    syn=synack=udp=total_bytes=ip_packets=0
    for p in packets:
        if IP not in p:continue
        ip=p[IP];sources[ip.src]+=1;destinations[ip.dst]+=1;total_bytes+=len(p);ip_packets+=1
        if TCP in p:
            tcp=p[TCP];key=(ip.src,ip.dst,tcp.sport,tcp.dport);flows[key][0]+=1;flows[key][1]+=len(p);flows[key][2].append(packet_time(p));ports[ip.src].add(tcp.dport)
            flags=int(tcp.flags)
            if flags&2 and not flags&16:syn+=1
            if flags&2 and flags&16:synack+=1
        elif UDP in p:udp+=1
        communications[(ip.src,ip.dst)].append(packet_time(p))
        if DNS in p and DNSQR in p:
            try:
                q=p[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if q:dns_queries.append(q)
            except:pass
    if not ip_packets:return "No Threat",0,"No IPv4 packets available for analysis",scores
    t=[packet_time(p) for p in packets];duration=max(t)-min(t);rate=len(packets)/max(duration,1);syn_rate=syn/max(duration,1);synack_ratio=synack/max(syn,1)
    if syn>=30 and syn_rate>=20 and synack_ratio<.30:scores["SYN Flood"]=min(100,70+int(min(30,syn_rate/10)))
    non_quic=sum(1 for p in packets if UDP in p and p[UDP].sport not in(443,8443) and p[UDP].dport not in(443,8443))
    if non_quic>=100 and udp/max(len(packets),1)>.70 and rate>=50:scores["UDP Amplification"]=75
    if len(sources)>=30 and rate>=50:scores["Source Flood"]=min(100,60+len(sources)//10)
    if max((len(x) for x in ports.values()),default=0)>=20:scores["Port Scanning"]=85
    if len(dns_queries)>=10:
        a=sum(map(len,dns_queries))/len(dns_queries);e=sum(entropy(x) for x in dns_queries)/len(dns_queries);l=sum(len(x)>=45 for x in dns_queries)
        if l>=5 and a>=30 and e>=3.2:scores["DGA / DNS Tunnelling"]=80
    encrypted=sum(v[0]>=20 and v[1]>=30000 and k[3] in(443,8443) for k,v in flows.items())
    if encrypted>=10:scores["Encrypted Traffic Anomaly"]=65
    large=sum(v[1]>=300000 for v in flows.values())
    if large>=3 or total_bytes>=5000000:scores["Data Exfiltration"]=75
    for ts in communications.values():
        if len(ts)<15:continue
        ts.sort();iv=[ts[i]-ts[i-1] for i in range(1,len(ts)) if ts[i]-ts[i-1]>=.5]
        if len(iv)>=10:
            m=statistics.median(iv);r=sum(abs(x-m)<=m*.15 for x in iv)/len(iv)*100
            if ts[-1]-ts[0]>=20 and r>=75:scores["C2 Beaconing"]=80;break
    attack,score=max(scores.items(),key=lambda x:x[1])
    if score<THRESHOLD:return "No Threat",0,"No suspicious pattern crossed the alert threshold",scores
    evidence={
        "SYN Flood":f"SYN={syn}, rate={syn_rate:.1f}/s, SYN/ACK ratio={synack_ratio:.2f}",
        "UDP Amplification":f"UDP={non_quic}, rate={rate:.1f}/s",
        "Source Flood":f"{len(sources)} unique sources, packet rate={rate:.1f}/s",
        "C2 Beaconing":"Periodic communication pattern detected",
        "DGA / DNS Tunnelling":f"{len(dns_queries)} DNS queries analyzed",
        "Encrypted Traffic Anomaly":f"{encrypted} persistent encrypted flows",
        "Port Scanning":f"Source contacted {max((len(x) for x in ports.values()),default=0)} destination ports",
        "Data Exfiltration":f"{large} large flows, {total_bytes/1024/1024:.2f} MB total"
    }
    return attack,score,evidence.get(attack,"Multiple indicators matched"),scores

def alert(attack,score,evidence,ml_attack,ml_confidence):
    data={"timestamp":datetime.now(timezone.utc).isoformat(),"threat_class":attack,"risk_score":score,"ml_prediction":ml_attack,"ml_confidence":round(ml_confidence*100,2),"supporting_evidence":evidence,"analysis_mode":"Passive / Read-Only","payload_inspection":False,"blocking":False}
    print("\n"+"="*60+"\n🚨 THREAT ALERT\n"+json.dumps(data,indent=2)+"\n"+"="*60)

if __name__=="__main__":
    path=input("PCAP path: ").strip("'\"")
    try:
        packets=rdpcap(path)
        features=extract_features(packets)
        ml_attack,ml_confidence=predict_ml(features)
        print("\nML PREDICTION:")
        print("Threat:",ml_attack)
        print("Confidence:",f"{ml_confidence*100:.2f}%")
        attack,score,evidence,scores=analyze(packets)
        print(f"\nRESULT: {attack} | {score}/100")
        print("Evidence:",evidence)
        print("Scores:",scores)
        if attack!="No Threat":alert(attack,score,evidence,ml_attack,ml_confidence)
    except Exception as error:print("ERROR:",error)