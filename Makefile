# Compiler
CXX = g++

# Compiler flags, add more if needed
CXXFLAGS = 

# Library paths, add with -L if needed
LDFLAGS = -L/usr/local/lib

# Libraries to link against, add with -l
LDLIBS = -ltss2-fapi -lssl -lcrypto

# Source files
SOURCES = demo.cpp sources/sign.cpp sources/create_key.cpp sources/verify.cpp sources/file_util.cpp sources/fapi_util.cpp sources/crypto_operations.cpp

# Target binary
TARGET = tpmProjectApp

# Default rule
all: $(TARGET)

# Rule for building the target
$(TARGET): $(SOURCES)
	$(CXX) -o $@ $(CXXFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS)

# Rule for cleaning up
clean:
	rm -f $(TARGET)

# Additional rules can be added here

