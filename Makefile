CC = gcc

CFLAGS = -Wpedantic # -g 

TARGET = challenge

SRCS = src/checker.c

$(TARGET): 
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm $(TARGET)