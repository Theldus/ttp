TOOLSDIR = $(CURDIR)/tools
CC      ?= cc
CFLAGS   = -DUSE_BEARSSL
CFLAGS  += -I$(CURDIR)/../BearSSL/inc -I$(TOOLSDIR)
LDFLAGS  = -L$(CURDIR)/../BearSSL/build --static
LDLIBS  += -lbearssl

OBJS     = ttp.o base64.o bearssl-layer.o
OBJS    += $(TOOLSDIR)/files.o \
	       $(TOOLSDIR)/vector.o \
	       $(TOOLSDIR)/xmem.o \
	       $(TOOLSDIR)/names.o

.PHONY: all
all: ttp Makefile

ttp: $(OBJS)
clean:
	rm -f $(OBJS) ttp
