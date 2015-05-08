AR = $(CROSS_COMPILE)ar
CC = $(CROSS_COMPILE)gcc$(CC_VERSION)

OBJ_DIR = obj
SRC_DIR = src
BIN_DIR = bin
LIB_DIR = lib
TEST_DIR = test/src

LDFLAGS = -ggdb
ARFLAGS = -r
CCFLAGS = -ggdb -Wall -Wextra -Werror -Wswitch-default -Wwrite-strings \
	-O3 -Iinclude -Itest/include -std=gnu99 $(CFLAGS)

# TBD

all: $(LIB)

test: $(TEST_BIN)
	@$(TEST_BIN)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(LIB_DIR) $(SUBMIT_TAR)
