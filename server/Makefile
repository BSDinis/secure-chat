CC := gcc
INCLUDE := -I.. -I.
VPATH   := .:..
CFLAGS  := -Wall -Werror -fdiagnostics-color=always $(INCLUDE)
LDFLAGS := -L $(INCLUDE) -Wall -Werror -Wextra -fdiagnostics-color=always
LDLIBS  := -lssl -lcrypto

ifeq ($(strip $(OPTIM)), yes)
  CFLAGS += -O2
endif

ifneq ($(strip $(DEBUG)), no)
  CFLAGS += -g
endif

SOURCES := $(wildcard *.c) $(wildcard ../common/*.c)
OBJECTS := $(SOURCES:.c=.o)
TARGET  := server_main

all: $(TARGET)      ## compile and copy upstream
	cp $(TARGET) ..

-include autodep

../common/ssl_util.o: ../common/ssl_util.h

$(TARGET): $(OBJECTS)  ## compile target

.PHONY: clean
clean:  ## remove garbage in pwd and in common
	rm -f *.o vgcore* $(TARGET)
	rm -f ../common/*.o

depend : $(SOURCES) ## do the dependencies
	$(CC) $(INCLUDES) -MM $(SOURCES) > autodep

certs : ## create certificates
	make -C .. certs

help: ## display options
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
