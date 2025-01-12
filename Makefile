#
# TTP: Tiny TLS Proxy: a very simple TLS proxy server with
#                      focus on resource consumption.
#
# Made by Davidson Francis.
# This is free and unencumbered software released into the public domain.
#

TOOLSDIR = $(CURDIR)/BearSSL/tools
CC      ?= cc
CFLAGS   = -DUSE_BEARSSL -Wall
CFLAGS  += -I$(CURDIR)/BearSSL/inc -I$(TOOLSDIR) -Os
LDFLAGS  = --static

OBJS  = ttp.o base64.o bearssl-layer.o
OBJS += $(TOOLSDIR)/files.o \
		$(TOOLSDIR)/vector.o \
		$(TOOLSDIR)/xmem.o \
		$(TOOLSDIR)/names.o \
		$(TOOLSDIR)/certs.o \
		$(TOOLSDIR)/errors.o

.PHONY: all
all: ttp Makefile

ttp.o: ttp.c bearssl-layer.h
bearssl-layer.o: bearssl-layer.c bearssl-layer.h

ttp: $(OBJS) $(CURDIR)/BearSSL/build/libbearssl.a

$(CURDIR)/BearSSL/build/libbearssl.a:
	$(MAKE) -C $(CURDIR)/BearSSL CC="$(CC)" build/libbearssl.a

clean:
	rm -f  $(OBJS) ttp
	rm -fr $(CURDIR)/BearSSL/build
