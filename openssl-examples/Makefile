SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
HEADERS := $(wildcard *.h)
TARGETS := examples

COMMON   := -O2 -Wall
CFLAGS   := $(CFLAGS) $(COMMON) $(shell pkg-config --cflags openssl)
CC       := gcc
LDADD    :=  $(shell pkg-config --libs openssl) -lcrypto -lssl
LD       := $(CC)

all : $(TARGETS)
.PHONY : all

# {{{ for debugging
debug : CFLAGS += -g -DDEBUG=1 -O0
debug : $(TARGETS)
.PHONY : debug
# }}}

$(OBJECTS) : %.o : %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGETS) : % : %.o
	$(LD) -o $@ $^ $(LDADD)

.PHONY : clean
clean :
	rm -f $(OBJECTS) $(TARGETS)
