CXX = g++
CXXFLAGS = -std=c++11

all: 1m-block

1m-block: main.cpp
	$(CXX) $(CXXFLAGS) -o 1m-block main.cpp -lnetfilter_queue

clean:
	rm -f 1m-block
