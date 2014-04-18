CC   = g++
LINK = g++


LFLAGS        = -g -Wall 
INCPATH       = 	-I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include  \
					 -I/usr/include/pbc -I/usr/local/include/pbc \
					 -I../../include/


LIBS = -O3 -Wall \
	-lglib-2.0   \
	-Wl,-rpath /usr/local/lib -lpbc \
	-lcrypto -lgmp \
	../../lib/libJerasure.a
#-L../lib -lJerasure


SOURCES       =	encryption.cpp common.cpp
OBJ           = $(SOURCES:.cpp=.o)
DEPEND         = ../../lib/libJerasure.a  common.o
TARGETS        =  encryption

all: $(TARGETS) $(OBJ)

encryption: encryption.o $(DEPEND)
	$(LINK) -o $@ $^ $(LIBS)

$(OBJ): %.o: %.cpp
	$(CC)  -c $< $(INCPATH) $(LFLAGS)  -o $@

.PHONY:clean
clean:
	rm -f $(OBJ) $(TARGETS) *~
	
