CFLAGS := -Wall -Wextra -Werror -g -O0
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
	
all: $(LIB) $(SERVER)
	
$(LIB): $(LIB_OBJS)
	cc -dynamiclib $^ -o $@
	
$(SERVER): $(SERVER_OBJS)
	cc $< -o $(SERVER) -L. -l9p
	
clean:
	rm -f $(LIB_OBJS) $(SERVER_OBJS)
	
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
