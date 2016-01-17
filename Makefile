CC = gcc
TARGET = parser_test
SOURCES = *.c
LD_FLAGS = -lxml2
INCLUDE_FLAGS = -I/usr/include/libxml2
DBG_FLAGS = -g 

all: parser 

parser: $(SOURCES)
	$(CC) -o $(TARGET) $(INCLUDE_FLAGS) $(SOURCES) $(LD_FLAGS)

debug: $(SOURCES)
	$(CC) -o $(TARGET) $(INCLUDE_FLAGS) $(SOURCES) $(LD_FLAGS) $(DBG_FLAGS)

clean:
	rm -f $(TARGET)
