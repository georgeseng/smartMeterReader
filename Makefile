CC = cd /root/programming/smartMeterReader; gcc
CC = /usr/bin/gcc
#-g
#-Wall
REMOTE_OLD = ssh root@192.168.5.8
REMOTE = 
RSYNC = /usr/bin/rsync -ru ge@192.168.5.22:~/raspberrypi/smartMeterReader /root/programming/

#192.168.1.196

#OBJECTS = lcd.c

default: all
all: rsync smartyMeterReader

rsync:
	$(REMOTE) $(RSYNC)

main.o: main.c
	$(REMOTE) $(CC) -c /Users/ge/raspberrypi/smartyMeterReader/main.c

smartMeterReader: main.o
	#lcd.o lcdInterface.o rawData.o notImplemented.o settings.o records.o about.o raspberry.o elm.o rs232.o moreData.o
	#lcd.o lcdInterface.o rawData.o notImplemented.o settings.o records.o about.o raspberry.o elm.o rs232.o moreData.o -lstdc++; cp a.out ../carLcd_bin/"
	$(REMOTE) $(CC) -o smartMeterReader main.o -lcrypto

clean:
	rm -f *.o
	rm -f smartMeterReader
