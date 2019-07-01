CC                  = gcc
CCC                 = g++

INCLUDE_DIRS        = -I . \
                      -I ../include

LIB_LOOKUP_DIRS     = -L ../lib

LIBS                = -lplist \
                      -lcryptopp

CCFLAGS             = -pthread
CCCFLAGS            = -pthread

OBJ_CPPATV          = main.o \
                      simpleHttpClient.o

TARGET              = cppatv

all: main

main: $(OBJ_CPPATV)
	$(CCC) $(OBJ_CPPATV) $(LIB_LOOKUP_DIRS) $(LIBS) $(CCCFLAGS) -o $(TARGET)

#tells how to make an *.o object file from an *.c file
%.o: %.c
	$(CC) -c $(INCLUDE_DIRS) $< $(CCFLAGS) -o $@

#tells how to make an *.o object file from an *.cpp file
%.o: %.cpp
	$(CCC) -c $(INCLUDE_DIRS) $< $(CCCFLAGS) -o $@

clean:
	rm -f *.o
	rm -f $(TARGET)
