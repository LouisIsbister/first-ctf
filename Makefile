CC = gcc

CFLAGS = -Wall -pedantic # -g 

TARGET = challenge

SRCS = src/interpreter.c

$(TARGET): 
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm $(TARGET)