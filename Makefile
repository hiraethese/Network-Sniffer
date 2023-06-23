CC = g++
CFLAGS = -std=c++11
LIBS = -lpcap

all: ipk-sniffer

ipk-sniffer: ipk-sniffer.cpp
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f ipk-sniffer
