# Cyber Behavirol Science

UCAS Cyber Behavior Science homework project </br>
Extract basic IP,TCP info and more specific info such as Cipher Suite, Server Name from TLS packets

## project structure

├── include  
│   &emsp;├── header.h // Ethernet, IP, TCP header format defined in here  
│   &emsp;├── tls.h  // structs related to TLS format defined in here  
│   &emsp;└── util.h  // global data and utilies  
├── main.c &emsp;// read packet one by one from pcap file and extrac IP, TCP info  
├── Makefile  
├── memcheck.sh &emsp;// use valgrind to check memory leak  
├── output.txt  
├── pcap  &emsp;// pcap files  
├── README.md  
└── tls_info_extr.c &emsp;// extract info specifically from TLS packets  

## dependencies

libpcap: `sudo apt install libpcap-dev`
