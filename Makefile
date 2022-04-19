CC ?=gcc
CFLAGS = -Wall -g
OBJ=main.c tls_info_extr.c
OUT=main
LDFLAGS=-lpcap

all:$(OBJ)
	$(CC) -o $(OUT) $^  $(CFLAGS) $(LDFLAGS)

.PHONY:clean
clean:
	@echo $(CC)
	rm -rf main