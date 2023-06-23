## Project 2 - ZETA: Network sniffer
Author: Baturov Illia (xbatur00)

## Project structure
My project has several parts. Firstly, I created global variables for each protocol, the number of packets to process, and the string to filter, as well as the device we'll be using. The important part is the argument handling, which I implemented with the function getopt_long(). This function is able to detect both long arguments and short ones. After processing the arguments, depending on the global booleans, each packet will be filtered. I use the main() function to open a session for an Ethernet device. When the session has opened successfully, you can start receiving a certain number of packets using the function pcap_loop(). As many packets will be written as specified in the global variable number_of_packets. The function pcap_loop() uses a callback function print_packet_info() that will be run for each packet. With the help of it we can get the information we need from the packet.

## Necessary theory
A packet sniffer is a tool used to analyze network traffic. It works by capturing data packets that are being transmitted over a network and then analyzing the contents of these packets. You can filter packets by different criteria, by network interface, by protocol or by port number, for example.

A network interface is a hardware component that enables a device to connect to a computer network. When a network interface receives a packet, it examines the packet's header. From the header of the packet, we can get the content of the packet, its source and destination, for example. In the sniffer, this feature is used to write out the data we need.

Also in the packet's header there is a protocol type of packet. Depending on the type of protocol, we use different headers from which we get data, different for each protocol. For example, only TCP and UDP protocols have ports.

## Code inspiration
To write a code for functions that receive packets, I was inspired by: https://www.tcpdump.org/pcap.html. This includes detecting the device, opening the session, compiling the filter, as well as looping through the received packets.

To understand how filter compilation works, I used different sites like this one: https://linux.die.net/man/7/pcap-filter. This helped me convert the text filter to the format that the sniffer needs.

It was also important for the implementation to know the number of protocols that I took from here: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml.

## Project testing

```
sudo ./ipk-sniffer
enp0s3
any
lo
nflog

```

```
sudo ./ipk-sniffer -i enp0s3 --tcp
timestamp: 2023-04-17T21:09:16.120+0000
src MAC: 52:54:00:12:35:02
dst MAC: 08:00:27:56:aa:92
frame length: 94 bytes
src IP: 147.229.177.163
dst IP: 10.0.2.15
src port: 443
dst port: 47096

0x0000: 08 00 27 56 aa 92 52 54 00 12 35 02 08 00 45 00 ..'V..RT ..5...E.
0x0010: 00 50 ba b1 00 00 40 06 6e 5f 93 e5 b1 a3 0a 00 .P....@. n_......
0x0020: 02 0f 01 bb b7 f8 e8 b4 93 33 e7 11 56 84 50 18 ........ .3..V.P.
0x0030: ff ff 1a 16 00 00 17 03 03 00 23 3b d0 2d cd 4d ........ ..#;.-.M
0x0040: 89 14 d6 8c f6 b8 60 55 d3 f7 33 1b bb 33 92 32 ......`U ..3..3.2
0x0050: b2 0f f5 ca 21 18 4f 92 b7 28 cd f1 4d 42 00 00 ....!.O. .(..MB..

```

```
sudo ./ipk-sniffer -i enp0s3 --udp -n 3
timestamp: 2023-04-17T21:10:23.310+0000
src MAC: 08:00:27:56:aa:92
dst MAC: 52:54:00:12:35:03
frame length: 106 bytes
src IP: 10.0.2.15
dst IP: 10.0.2.3
src port: 54526
dst port: 53

0x0000: 52 54 00 12 35 03 08 00 27 56 aa 92 08 00 45 00 RT..5... 'V....E.
0x0010: 00 5c ac 05 40 00 40 11 76 7a 0a 00 02 0f 0a 00 .\..@.@. vz......
0x0020: 02 03 d4 fe 00 35 00 48 18 6b 39 91 01 00 00 01 .....5.H .k9.....
0x0030: 00 00 00 00 00 01 13 63 6f 6e 74 65 6e 74 2d 73 .......c ontent-s
0x0040: 69 67 6e 61 74 75 72 65 2d 32 03 63 64 6e 07 6d ignature -2.cdn.m
0x0050: 6f 7a 69 6c 6c 61 03 6e 65 74 00 00 01 00 01 00 ozilla.n et......
0x0060: 00 29 04 b0 00 00 00 00 00 00 00 00 00 00 00 00 .)...... ........

timestamp: 2023-04-17T21:10:23.312+0000
src MAC: 52:54:00:12:35:02
dst MAC: 08:00:27:56:aa:92
frame length: 260 bytes
src IP: 10.0.2.3
dst IP: 10.0.2.15
src port: 53
dst port: 54526

0x0000: 08 00 27 56 aa 92 52 54 00 12 35 02 08 00 45 00 ..'V..RT ..5...E.
0x0010: 00 f6 ba ba 00 00 40 11 a7 2b 0a 00 02 03 0a 00 ......@. .+......
0x0020: 02 0f 00 35 d4 fe 00 e2 b7 e3 39 91 81 80 00 01 ...5.... ..9.....
0x0030: 00 03 00 00 00 01 13 63 6f 6e 74 65 6e 74 2d 73 .......c ontent-s
0x0040: 69 67 6e 61 74 75 72 65 2d 32 03 63 64 6e 07 6d ignature -2.cdn.m
0x0050: 6f 7a 69 6c 6c 61 03 6e 65 74 00 00 01 00 01 c0 ozilla.n et......
0x0060: 0c 00 05 00 01 00 00 00 5e 00 3a 18 63 6f 6e 74 ........ ^.:.cont
0x0070: 65 6e 74 2d 73 69 67 6e 61 74 75 72 65 2d 63 68 ent-sign ature-ch
0x0080: 61 69 6e 73 04 70 72 6f 64 09 61 75 74 6f 67 72 ains.pro d.autogr
0x0090: 61 70 68 08 73 65 72 76 69 63 65 73 06 6d 6f 7a aph.serv ices.moz
0x00a0: 61 77 73 c0 2c c0 41 00 05 00 01 00 00 00 5e 00 aws.,.A. ......^.
0x00b0: 38 04 70 72 6f 64 18 63 6f 6e 74 65 6e 74 2d 73 8.prod.c ontent-s
0x00c0: 69 67 6e 61 74 75 72 65 2d 63 68 61 69 6e 73 04 ignature -chains.
0x00d0: 70 72 6f 64 0b 77 65 62 73 65 72 76 69 63 65 73 prod.web services
0x00e0: 06 6d 6f 7a 67 63 70 c0 2c c0 87 00 01 00 01 00 .mozgcp. ,.......
0x00f0: 00 00 5e 00 04 22 a0 90 bf 00 00 29 ff d6 00 00 ..^..".. ...)....
0x0100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ........ ........

timestamp: 2023-04-17T21:10:23.312+0000
src MAC: 08:00:27:56:aa:92
dst MAC: 52:54:00:12:35:03
frame length: 106 bytes
src IP: 10.0.2.15
dst IP: 10.0.2.3
src port: 54526
dst port: 53

0x0000: 52 54 00 12 35 03 08 00 27 56 aa 92 08 00 45 00 RT..5... 'V....E.
0x0010: 00 5c ac 06 40 00 40 11 76 79 0a 00 02 0f 0a 00 .\..@.@. vy......
0x0020: 02 03 d4 fe 00 35 00 48 18 6b f3 96 01 00 00 01 .....5.H .k......
0x0030: 00 00 00 00 00 01 13 63 6f 6e 74 65 6e 74 2d 73 .......c ontent-s
0x0040: 69 67 6e 61 74 75 72 65 2d 32 03 63 64 6e 07 6d ignature -2.cdn.m
0x0050: 6f 7a 69 6c 6c 61 03 6e 65 74 00 00 1c 00 01 00 ozilla.n et......
0x0060: 00 29 04 b0 00 00 00 00 00 00 00 00 00 00 00 00 .)...... ........

```

## Bibliography
* http://www.tcpdump.org/
* http://en.wikipedia.org/wiki/Pcap
* https://www.geeksforgeeks.org/introduction-to-sniffers/
