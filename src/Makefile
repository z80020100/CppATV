SRC         = $(wildcard *.cpp)
CC          = g++
INCLUDES    = -I . \
              -I ../include
LIBS        = -lplist \
              -lcryptopp
LIBS_LINK   = -L ../lib
FLAGS       = -pthread
TARGET      = cppatv

.PHONY: clean

all:
	$(CC) $(SRC) $(INCLUDES) $(LIBS_LINK) $(LIBS) $(FLAGS) -o $(TARGET)

clean:
	rm -rf *.o $(TARGET)
