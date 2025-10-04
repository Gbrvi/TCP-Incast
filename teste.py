throughput_in_window = []

try:
    with open("/home/almeida/projects/TCP-Incast/run_40_hosts_cubic/throughput_data.txt", 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                timestamp = float(parts[0])
                throughput = float(parts[1])
            if 5 < timestamp < 130:
                throughput_in_window.append(throughput)
except Exception as ex:
    print("Deu ruim")


total = 0

for x in throughput_in_window:
    total += x

print(total/len(throughput_in_window))

                