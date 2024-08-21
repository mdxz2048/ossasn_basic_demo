OSSASN1 = /home/caeri/lzp/ossasn1/download/ossasn1/linux-x86-64.trial/11.3.1

include /home/caeri/lzp/ossasn1/download/ossasn1/linux-x86-64.trial/11.3.1/samples/common.mak


CC = gcc
CFLAGS = -Wall -I. -L. -g
TARGET = demo
SRC = demo.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

demo: demo.o ltev-csae-157-2020-defs.o $(OSSSOED)
	$(LD) $(LDFLAGS) -o demo demo.o ltev-csae-157-2020-defs.o $(OSSSOED) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -DOSSPRINT -o $@ $?

clean:
	rm -f $(TARGET) $(OBJ)
