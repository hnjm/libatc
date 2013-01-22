CC = gcc
CXX = g++
LD = g++

CXXFLAGS = -DNODEBUG -O3 -std=gnu++0x
LIBS = -latc -lz
LIBDIRS = -L.

TARGET = libatc.a
OBJS := $(patsubst %.cpp,%.o,$(wildcard *.cpp))
OBJS += $(patsubst %.c,%.o,$(wildcard *.c))

TEST_TARGET = ./test/test
TEST_OBJS := ./test/test.o ./test/crc.o

all: $(TARGET) $(TEST_TARGET)

$(TARGET): $(OBJS)
	ar rv $(TARGET) $(OBJS)

$(TEST_TARGET): $(TARGET) $(TEST_OBJS)
	$(LD) $(CXXFLAGS) -o $(TEST_TARGET) $(TEST_OBJS) $(LIBS) $(LIBDIRS)

test: $(TEST_TARGET)
	./test/test

clean:
	@rm -f $(OBJS) $(TARGET)
	@rm -f $(TEST_OBJS) $(TEST_TARGET)
