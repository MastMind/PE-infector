CC=gcc
CFLAGS=-c -Wall
LDFLAGS=-static
SOURCES=*.c
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
EXECUTABLE=PE-infector

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(@) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $< -o $(@)

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
