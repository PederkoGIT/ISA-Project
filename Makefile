.PHONY: all clean tar

CFLAGS := -g -Wall -Wextra -pedantic
LDFLAGS := -lpcap
PROG_OBJS := dns-monitor.o

all: 
  gcc $(CFLAGS) -o dns-monitor dns-monitor.c $(LDFLAGS)

clean:
	rm -f $(PROG_OBJS) dns-monitor xpalen06.tar

tar:
	tar -cvf xpalen06.tar dns-monitor.c dns-monitor.h Makefile test_pcap.pcapng