CC?=gcc 
CFLAGS=-Wall -g -fsanitize=address
SRC=main.c tls_info_extr.c
OUT=main
LDFLAGS=-lpcap 

all:$(SRC)
	$(CC) -o $(OUT) $^  $(CFLAGS) $(LDFLAGS)

.PHONY:clean
clean:
	@echo $(CC)
	rm -rf main