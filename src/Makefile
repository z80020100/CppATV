CC = g++
INCLUDE = .
TARGET = cppatv

.PHONY: clean

all: cppatv

cppatv: simpleHttpClient.o main.o 
	$(CC) simpleHttpClient.o main.o -o $(TARGET)

simpleHttpClient.o: simpleHttpClient.cpp
	$(CC) -I$(INCLUDE) -c simpleHttpClient.cpp

main.o: main.cpp
	$(CC) -I$(INCLUDE) -c main.cpp

clean:
	rm -rf *.o $(TARGET)
