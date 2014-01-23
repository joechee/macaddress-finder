all: network.c brand.c
	gcc network.c brand.c -lwpcap -lgnurx -o finder.exe


clean:
	rm *.exe

