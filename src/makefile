LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -std=c++0x -pthread

clean:
	rm -f send-arp-test *.o
