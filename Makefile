SRCDIR:=`pwd`

CC?=gcc 
CFLAGS=-Wall -g -fsanitize=address -I $(SRCDIR)/include
LDFLAGS=-lpcap 

SRC=main.c tls_info_extr.c
OUT=main


all:$(SRC)
	$(CC) -o $(OUT) $^  $(CFLAGS) $(LDFLAGS)

.PHONY:clean
clean:
	@echo $(SRCDIR)
	rm -rf main