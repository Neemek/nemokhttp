.PHONY: test-file install

CC := g++
CC_FLAGS := -Wall

MAIN_FILE := http.cpp
LIB_NAME := http

DEPENDENCY_FOLDER := lib
DEPENDENCY_FLAGS := -lss -lcrypto

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

lib/libhttp.so: http.cpp
	$(CC) -c -L$(DEPENDENCY_FOLDER)/ -o $(DEPENDENCY_FOLDER)/lib$(LIB_NAME).o -fPIC $(MAIN_FILE) $(CC_FLAGS) $(DEPENDENCY_FLAGS)
	$(CC) -o $(DEPENDENCY_FOLDER)/lib$(LIB_NAME).so -shared $(DEPENDENCY_FOLDER)/lib$(LIB_NAME).o $(CC_FLAGS)

# $(LIB_NAME).out: main.cpp http.cpp
#	  $(CC) -o $(LIB_NAME).out main.cpp http.cpp 

test.out: test.cpp
	$(CC) -L$(DEPENDENCY_FOLDER)/  -o test.out test.cpp -l$(LIB_NAME) $(CC_FLAGS) $(DEPENDENCY_FLAGS)

install:
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 lib/libhttp.so $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/
	install -m 644 http.hpp $(DESTDIR)$(PREFIX)/lib/


# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/neemek/http/lib
test-exe: $(DEPENDENCY_FOLDER)/lib$(LIB_NAME).so test.out

