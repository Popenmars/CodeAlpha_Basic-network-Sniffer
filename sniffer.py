from scapy.all import sniff, IP, TCP, UDP, Raw

def observe(mssg):
    print("="*60)

    if IP in mssg:
        layer1 = mssg[IP]
        print(f'[IP] {layer1.src} --> {layer1.dst}')
        print (f'  Protocol:{layer1.proto}')

        if TCP in mssg:
            layer2 = mssg[TCP]
            print(f'[TCP] Src Port: {layer2.sport}')

        elif UDP in mssg:
            layer3 = mssg[UDP]
            print(f'[UDP] Src Port: {layer3.sport}')

        if Raw in mssg:
            data = mssg[Raw].load
            try:
                decoded = data.decode('utf-8', errors='replace')
            except:
                decoded = str(data)
            print(f'[Payload] {decoded[:100]}')

    else:
        print('No IP Packet')

print('Sniffing... Press Ctrl+c to stop.\n')
sniff(prn = observe, store = False)


    