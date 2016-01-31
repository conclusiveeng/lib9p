CFLAGS := -Wall -Wextra -Werror -g -O0
BUILD_DIR := build

LIB_SRCS := \
	pack.c \
	connection.c \
	request.c \
	log.c \
	hashtable.c \
	utils.c \
	sbuf/sbuf.c \
	transport/socket.c \
	backend/fs.c
	
SERVER_SRCS := \
	example/server.c
	
LIB_OBJS := $(LIB_SRCS:.c=.o)
SERVER_OBJS := $(SERVER_SRCS:.c=.o)
LIB := lib9p.dylib
SERVER := server
	
all: build $(LIB) $(SERVER)
	
$(LIB): $(LIB_OBJS)
	cc -dynamiclib $^ -o build/$@
	
$(SERVER): $(SERVER_OBJS) $(LIB)
	cc $< -o build/$(SERVER) -Lbuild/ -l9p
	
clean:
	rm -rf build
	
build:
	mkdir build
	
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
