CXX		= g++ --std=c++11 -Wall -fPIC -O2 -I. -I../include
DEL_FILE		= rm -f
OBJECTS	= \
	analyzer.o \
	connection.o \
	pcap_reader.o \
	main.o \
	packet.o \
	config.o \

TARGET = ../bin/pcap_analyze
FLAGS_LIB = -L$(CURDIR)/../lib -Wl,-rpath -Wl,$(CURDIR)/../lib

all: $(TARGET)

clean:
	$(DEL_FILE) $(OBJECTS) *~

clear: clean
	$(DEL_FILE) ../bin ../log

packet.o: packet.h packet.cpp
	$(CXX) -c packet.cpp

config.o: config.h config.cpp
	$(CXX) -c config.cpp

connection.o: connection.h connection.cpp packet.h config.h
	$(CXX) -c connection.cpp

analyzer.o: analyzer.h analyzer.cpp config.h
	$(CXX) -c analyzer.cpp

pcap_reader.o: pcap_reader.h pcap_reader.cpp connection.h analyzer.h packet.h config.h
	$(CXX) -c pcap_reader.cpp

main.o: main.cpp pcap_reader.h config.h
	$(CXX) -c main.cpp

$(TARGET): pcap_reader.o analyzer.o connection.o main.o packet.o config.o
	mkdir -p ../bin ../log
	$(CXX) -o $@ pcap_reader.o analyzer.o connection.o main.o packet.o config.o \
			-lpcap -lfinddecryptor -ldetectsimilar $(FLAGS_LIB)

