CC = gcc

CFLAGS = -g -Wall -pedantic 

TARGET = challenge

SRCS = src/checker.c

$(TARGET): 
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm $(TARGET)