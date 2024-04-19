SOURCES := $(wildcard *.c src/**/*.c *.cpp src/**/*.cpp)
OBJECTS := $(SOURCES:.c=.o)
OBJECTS := $(OBJECTS:.cpp=.o)
HEADERS := $(wildcard *.h include/*.h)

COMMON   := -O2 -Wall -Wformat=2 -Wno-format-nonliteral -DNDEBUG
CFLAGS   := $(CFLAGS) $(COMMON) -I/opt/homebrew/opt/openssl/include -I/opt/homebrew/Cellar/gmp/6.3.0/include
CXXFLAGS := $(CXXFLAGS) $(COMMON) -I/opt/homebrew/opt/openssl/include -I/opt/homebrew/Cellar/gmp/6.3.0/include
CC       := gcc
CXX      := g++
LD       := $(CC)
LDFLAGS  := $(LDFLAGS) -L/opt/homebrew/opt/openssl/lib # -L/path/to/libs/ -L/opt/homebrew/Cellar/gmp/6.3.0/include
LDADD    := -lpthread -lcrypto -lgmp -lssl -lcrypto $(shell pkg-config --libs gtk+-3.0)
INCLUDE  := $(shell pkg-config --cflags gtk+-3.0)
DEFS     := # -DLINUX

TARGETS  := chat dh-example

IMPL := chat.o
ifdef skel
IMPL := $(IMPL:.o=-skel.o)
endif

.PHONY : all
all : $(TARGETS)

# {{{ for debugging
DBGFLAGS := -g3 -UNDEBUG -O0
debug : CFLAGS += $(DBGFLAGS)
debug : CXXFLAGS += $(DBGFLAGS)
debug : all
.PHONY : debug
# }}}

chat : $(IMPL) dh.o keys.o util.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

dh-example : dh-example.o dh.o keys.o util.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

%.o : %.cpp $(HEADERS)
	$(CXX) $(DEFS) $(INCLUDE) $(CXXFLAGS) -c $< -o $@

%.o : %.c $(HEADERS)
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c $< -o $@

.PHONY : clean
clean :
	rm -f $(TARGETS) $(OBJECTS)

# vim:ft=make:foldmethod=marker:foldmarker={{{,}}}
