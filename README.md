# netbs

ucas network behavioral science homework project </br>
extract basic IP,TCP info and more specific info such as Cipher Suite, Server Name from TLS packets

## project structure

├── header.h &emsp;&emsp;// Ethernet, IP, TCP header format defined in here</br>
├── main</br>
├── main.c &emsp;&emsp;// read packet one by one from pcap file</br>
├── Makefile</br>
├── output.txt &emsp;// info extrated from TLS packets printed in this txt file</br>
├── README.md</br>
├── tls.h &emsp;&emsp;// structs related to TLS format defined in here</br>
├── tls_info_extr.c &emsp;&emsp;// extract info specifically from TLS packets</br>
└── util.h &emsp;&emsp;// global stuffs and utilies

## dependencies

libpcap: sudo apt install libpcap-dev

## statistics
