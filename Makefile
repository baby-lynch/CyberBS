CC?=gcc 
CFLAGS=-Wall -g -fsanitize=address -I $(SRCDIR)/include
LDFLAGS=-lpcap 

SRCDIR:=`pwd`
SRC+=main.c 
SRC+=tls_info_extr.c
OUT=main


all:$(SRC)
	$(CC) -o $(OUT) $^  $(CFLAGS) $(LDFLAGS)

.PHONY:clean
clean:
	rm -rf main