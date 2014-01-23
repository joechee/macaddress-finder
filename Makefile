all: network.c brand.c
	gcc network.c brand.c -lwpcap -lgnurx -o test.exe


clean:
	rm *.exe

