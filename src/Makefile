

INCPATH       = 	-I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include  \
					 -I/usr/include/pbc -I/usr/local/include/pbc \
					 -I../include/

LFLAGS        = -g -Wall

all: pre
	make -C ./setup
	make -C ./keygen
	make -C ./encryption

pre:
	make -C ./jerasure	

	
	

.PHONY:clean 
clean:
	make -C ./setup clean
	make -C ./keygen clean
	make -C ./jerasure clean
	make -C ./encryption clean
	rm -f *~ 
	

	


