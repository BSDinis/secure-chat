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
HEADERS := $(wildcard *.h) $(wildcard ../common/*.h)
OBJECTS := $(SOURCES:.c=.o)
TARGET  := client_main

all: $(TARGET)      ## compile and copy upstream
	cp $(TARGET) ..

-include autodep

$(TARGET): $(OBJECTS) $(HEADERS)  ## compile target

.PHONY: clean
clean:  ## remove garbage in pwd and in common
	rm -f *.o vgcore* $(TARGET)

depend : $(SOURCES) ## do the dependencies
	$(CC) $(INCLUDES) -MM $(SOURCES) > autodep

help: ## display options
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
