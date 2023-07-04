http.out: main.cpp http.cpp
	g++ -o http.out main.cpp http.cpp

lib/http.o lib/libhttp.so: http.cpp
	g++ -c -Llib/ -o lib/http.o -fPIC http.cpp -lssl -lcrypto
	gcc -o lib/libhttp.so -shared lib/http.o

test.out: test.cpp
	g++ -Llib/ -Wall -o test.out test.cpp -lhttp -lssl -lcrypto

# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/neemek/http/lib
discordreq: lib/libhttp.so test.out
	echo done

