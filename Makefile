CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread
TARGET = gurt
SOURCE = gurt.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE)

# Install with setuid permissions - run with 'sudo make install'
install: $(TARGET)
	sudo chown root:wheel ./$(TARGET)
	sudo chmod 4755 ./$(TARGET)

# Install to system directory - run with 'sudo make install-system'
install-system: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin..."
	sudo cp ./$(TARGET) /usr/local/bin/
	sudo chown root:wheel /usr/local/bin/$(TARGET)
	sudo chmod 4755 /usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: clean install install-system
