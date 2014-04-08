CC   = g++
LINK = g++


LFLAGS        = -g -Wall 
INCPATH       = 	-I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include  \
					 -I/usr/include/pbc -I/usr/local/include/pbc \


#LIBS          = -L/usr/lib/i386-linux-gnu -lQtGui -lQtCore -lpthread -L/usr/local/lib -lpcap
LIBS = -O3 -Wall \
	-lglib-2.0   \
	-Wl,-rpath /usr/local/lib -lpbc \
	-lcrypto -lgmp 

SOURCES       =	sys_init.cpp keygen.cpp
OBJ           = $(SOURCES:.cpp=.o)
TARGETS        =  setup keygen

all: $(TARGETS) $(OBJ)
	
setup: sys_init.o
	$(LINK) -o $@ $^ $(LIBS)

keygen: keygen.o
	$(LINK) -o $@ $^ $(LIBS)


$(OBJ): %.o: %.cpp
	$(CC)  -c $< $(INCPATH) $(LFLAGS) -o $@

install:
	@echo "nothing to do!"


.PHONY:clean
clean:
	rm -f $(OBJ) $(TERGET)
	
