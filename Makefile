LDLIBS= -lpcap -lncurses

all: signal-strength


parse.o: parse.h parse.cpp


signal-strength: main.o parse.o hdr.h
	$(LINK.cc) -w $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o
clean:
	rm -f signal-strength *.o

