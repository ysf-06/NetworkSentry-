CC ?= gcc
CFLAGS = -O3 -Wall -Wextra -Werror -Iinclude

ifeq ($(OS),Windows_NT)
    SHARED_EXT = dll
    TEST_BIN = test_packet_parser.exe
    LDFLAGS =
else
    SHARED_EXT = so
    CFLAGS += -fPIC
    TEST_BIN = test_packet_parser
    LDFLAGS = -ldl
endif

SHARED_LIB = packet_parser.$(SHARED_EXT)

all: $(SHARED_LIB) $(TEST_BIN)

$(SHARED_LIB): src/packet_parser.c include/packet_parser.h
	$(CC) $(CFLAGS) -shared -DBUILDING_PACKET_PARSER src/packet_parser.c -o $(SHARED_LIB) $(LDFLAGS)

$(TEST_BIN): src/packet_parser.c src/test_packet_parser.c include/packet_parser.h
	$(CC) $(CFLAGS) -DBUILDING_PACKET_PARSER src/packet_parser.c src/test_packet_parser.c -o $(TEST_BIN) $(LDFLAGS)

test: $(SHARED_LIB) $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(SHARED_LIB) $(TEST_BIN)
