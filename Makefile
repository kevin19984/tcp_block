all : tcp_block

tcp_block: main.o boyer_moore.o makepacket.o
	g++ -std=c++11 -g -o tcp_block main.o boyer_moore.o makepacket.o -lnetfilter_queue -lpcap

boyer_moore.o: boyer_moore.cpp boyer_moore.h
	g++ -std=c++11 -g -c -o boyer_moore.o boyer_moore.cpp

makepacket.o: makepacket.cpp makepacket.h
	g++ -std=c++11 -g -c -o makepacket.o makepacket.cpp

main.o: main.cpp boyer_moore.h makepacket.h
	g++ -std=c++11 -g -c -o main.o main.cpp -lnetfilter_queue

clean:
	rm -f tcp_block
	rm -f *.o
