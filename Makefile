all: 1m-block

1m-block: 1m-block.c
	g++ -o main main.cpp -lnetfilter_queue

clean:
	rm -f main
