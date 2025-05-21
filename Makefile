all: 1m-block

1m-block: 1m-block.c
	g++ -o main main.c -lnetfilter_queue

clean:
	rm -f main
