# Compiler
CXX = g++

# Compiler flags, add more if needed
CXXFLAGS = 

# Library paths, add with -L if needed
LDFLAGS = -L/usr/local/lib

# Libraries to link against, add with -l
LDLIBS = -ltss2-fapi -lssl -lcrypto -lcurl

# Source files
SOURCES = modifiedDataCheckingJob.cpp /home/lukas/diplo/code/diplo/sources/verify.cpp /home/lukas/diplo/code/diplo/sources/file_util.cpp /home/lukas/diplo/code/diplo/sources/fapi_util.cpp 

# Target binary
TARGET = send_email

# Default rule
all: $(TARGET)

# Rule for building the target
$(TARGET): $(SOURCES)
	$(CXX) -o $@ $(CXXFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS)

# Rule for cleaning up
clean:
	rm -f $(TARGET)

# Additional rules can be added here

