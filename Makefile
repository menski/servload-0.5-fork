# $Id: Makefile 1901 2011-12-16 10:28:34Z umaxx $ */

# Copyright (c) 2011 Jörg Zinke <info@salbnet.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

CC=gcc
INSTALL=install
RM=rm -rf

PLATFORM=$(shell uname)
MACHINE?=$(shell uname -m)

PREFIX_Linux=/usr
PREFIX_OpenBSD=/usr/local
PREFIX=$(PREFIX_$(PLATFORM))

INCLUDEDIR=$(PREFIX)/include
LIBDIR_i386=$(PREFIX)/lib
LIBDIR_i686=$(PREFIX)/lib
LIBDIR_amd64=$(PREFIX)/lib
LIBDIR_x86_64=$(PREFIX)/lib64
LIBDIR=$(LIBDIR_$(MACHINE))
BINDIR=$(PREFIX)/bin

CCFLAGS= -Os -ansi -pedantic -W -Wall -Wbad-function-cast -Wcast-align
CCFLAGS+= -Wcast-qual -Wcomments -Wendif-labels -Winline -Wmissing-declarations
CCFLAGS+= -Wmissing-prototypes -Wnested-externs -Wno-div-by-zero -Wno-multichar
CCFLAGS+= -Wpointer-arith -Wredundant-decls -Wshadow -Wsign-compare
CCFLAGS+= -Wstrict-prototypes -Wundef -Wwrite-strings

CCFLAGS+=-Isrc -I/usr/include -I$(INCLUDEDIR)
CCFLAGS+=`pkg-config --cflags --silence-errors openssl`

CCFLAGS_Linux=-fPIC -D_BSD_SOURCE -D_XOPEN_SOURCE=600 -D_GNU_SOURCE
CCFLAGS_OpenBSD=
CCFLAGS+=$(CCFLAGS_$(PLATFORM))

LDFLAGS=-L/usr/lib -L$(LIBDIR) -lm
LDFLAGS+=`pkg-config --libs --silence-errors openssl || echo '-lssl'`

LDFLAGS_Linux=-lrt
LDFLAGS_OpenBSD=
LDFLAGS+=$(LDFLAGS_$(PLATFORM))

OBJECTS=servload.o

all: servload

.c.o:
	$(CC) $(CCFLAGS) -o $@ -c $<

servload: $(OBJECTS)
	$(CC) $(LDFLAGS) -o servload $(OBJECTS)

test: servload
	test/test.sh

clean:
	$(RM) $(OBJECTS)
	$(RM) servload.core
	$(RM) servload

install: servload
	$(INSTALL) -m0755 servload $(BINDIR)

uninstall:
	$(RM) $(BINDIR)/servload

.PHONY: all test clean install uninstall
