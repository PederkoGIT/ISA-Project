.PHONY: all clean

CFLAGS := -g -Wall -Wextra -pedantic
LDFLAGS := -lpcap
PROG_OBJS := dns-monitor.o

all: dns-monitor

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

dns-monitor: $(PROG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(PROG_OBJS) dns-monitor