TARGET=topnviewerServer
SRCS	=$(wildcard *.cpp)
OBJECTS	=$(SRCS:.cpp=.o)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
	CPPFLAGS+=-I/Users/goka/android/sysroot/include
	LDFLAGS+=-L/Users/goka/android/sysroot/lib
else
	CXXFLAGS+=-I/root/android/sysroot/include
	LDFLAGS+=-L/root/android/sysroot/lib
endif

LDLIBS+=-lpcap

all: $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CXX) $(LDFLAGS) $(TARGET_ARCH) $(OBJECTS) $(LDLIBS) -o $(TARGET)

main.o: main.cpp
dot11.o: dot11.cpp
radiotap.o: radiotap.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o

