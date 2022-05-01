CC?=gcc 
CFLAGS=-Wall -g -fsanitize=address
LDFLAGS=-lpcap 

SRC=main.c tls_info_extr.c
OUT=main


all:$(SRC)
	$(CC) -o $(OUT) $^  $(CFLAGS) $(LDFLAGS)

.PHONY:clean
clean:
	rm -rf main