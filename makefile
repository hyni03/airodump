CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11
LDFLAGS = -lncurses -lpcap

all: airodump

airodump: main.o airodump.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

airodump.o: airodump.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o airodump
