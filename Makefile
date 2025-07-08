# Detect operating system
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2
TARGET = gurt
SOURCE = gurt.cpp

# OS-specific settings
ifeq ($(UNAME_S),Linux)
    CXXFLAGS += -pthread
    INSTALL_DIR = /usr/local/bin
    INSTALL_GROUP = root
    SUDO_CMD = sudo
endif

ifeq ($(UNAME_S),Darwin)
    CXXFLAGS += -pthread
    INSTALL_DIR = /usr/local/bin
    INSTALL_GROUP = wheel
    SUDO_CMD = sudo
endif

ifeq ($(OS),Windows_NT)
    TARGET = gurt.exe
    CXXFLAGS += -D_WIN32_WINNT=0x0601 -lws2_32 -liphlpapi
    INSTALL_DIR = C:/Windows/System32
    SUDO_CMD = 
    # Windows doesn't need pthread flag as it's built into MSVC
    ifeq ($(CXX),g++)
        CXXFLAGS += -pthread
    endif
endif

# Default fallback for other Unix-like systems
ifndef INSTALL_DIR
    CXXFLAGS += -pthread
    INSTALL_DIR = /usr/local/bin
    INSTALL_GROUP = root
    SUDO_CMD = sudo
endif

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE)

# Install with setuid permissions (Unix-like systems only)
install: $(TARGET)
ifeq ($(OS),Windows_NT)
	@echo "Note: Windows installation requires administrator privileges"
	copy $(TARGET) $(INSTALL_DIR)
else
	$(SUDO_CMD) chown root:$(INSTALL_GROUP) ./$(TARGET)
	$(SUDO_CMD) chmod 4755 ./$(TARGET)
endif

# Install to system directory
install-system: $(TARGET)
ifeq ($(OS),Windows_NT)
	@echo "Installing $(TARGET) to $(INSTALL_DIR)..."
	@echo "Note: Run as administrator for system installation"
	copy $(TARGET) $(INSTALL_DIR)
else
	@echo "Installing $(TARGET) to $(INSTALL_DIR)..."
	$(SUDO_CMD) cp ./$(TARGET) $(INSTALL_DIR)/
	$(SUDO_CMD) chown root:$(INSTALL_GROUP) $(INSTALL_DIR)/$(TARGET)
	$(SUDO_CMD) chmod 4755 $(INSTALL_DIR)/$(TARGET)
endif

clean:
ifeq ($(OS),Windows_NT)
	del /Q $(TARGET) 2>nul || echo "File not found"
else
	rm -f $(TARGET)
endif

# Show detected OS information
info:
	@echo "Detected OS: $(UNAME_S)"
ifeq ($(OS),Windows_NT)
	@echo "Target: $(TARGET)"
	@echo "Install directory: $(INSTALL_DIR)"
else
	@echo "Architecture: $(UNAME_M)"
	@echo "Target: $(TARGET)"
	@echo "Install directory: $(INSTALL_DIR)"
	@echo "Install group: $(INSTALL_GROUP)"
endif

.PHONY: clean install install-system info
