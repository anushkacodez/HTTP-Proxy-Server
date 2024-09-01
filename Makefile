# Compiler and linker
CXX = g++
LINKER = g++

# Compiler and linker flags
CXXFLAGS = -Wall -Wextra -O2 -std=c++17
LDFLAGS = -lws2_32 -lssl -lcrypto

# Output executable name
TARGET = proxy_server

# Source files
SRCS = main.cpp

# Object files (generated from the source files)
OBJS = $(SRCS:.cpp=.o)

# Default target - build the executable
all: $(TARGET)

# Rule to link object files into the final executable
$(TARGET): $(OBJS)
	$(LINKER) -o $@ $^ $(LDFLAGS)

# Rule to compile each .cpp file into a .o file
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	del $(OBJS) $(TARGET)
