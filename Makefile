CC ?=gcc
CFLAGS = -I ./includes

all:main.c tls_info_extr.c
	$(CC) -o main $^  $(CFLAGS) -lpcap

.PHONY:clean
clean:
	@echo $(CC)
	rm -rf main