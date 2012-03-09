DESTDIR =
PREFIX = /usr/local

LIB = libregex.a

AR = ar
CC = gcc
CFLAGS += -g -O3 -DSTDC_HEADERS
LDFLAGS += 

all: $(LIB)

$(LIB): regex.o
	rm -f $@
	$(AR) cq $@ $<

clean:
	rm -f *.o *.a

install: $(LIB)
	install -d $(DESTDIR)$(PREFIX)/include $(DESTDIR)$(PREFIX)/lib
	install -m 0644 regex.h $(DESTDIR)$(PREFIX)/include
	install -m 0644 $(LIB) $(DESTDIR)$(PREFIX)/lib
