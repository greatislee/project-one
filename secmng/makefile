.PHONY:clean all

WORKDIR=.
VPATH = ./src

CC=gcc
CFLGS= -g -I$(WORKDIR)/inc/
LIBFLAG = -L$(HOME)/itcast/1006_SECAPP/lib/


# BIN = keymngclient  keymngserver	
BIN = keymngserver keymngclient 
#testdbapi keymngserver

all:$(BIN)

keymngclient:keymngclient.o keymnglog.o keymngclientop.o myipc_shm.o keymng_shmop.o
	$(CC)  $(LIBFLAG) $^ -o $@ -lpthread -litcastsocket -lmessagereal 

# keymng_dbop.o 
keymngserver:keymngserver.o keymngserverop.o keymnglog.o myipc_shm.o keymng_shmop.o
	$(CC) $(LIBFLAG) $^ -o $@ -lpthread -litcastsocket -lmessagereal -lclntsh -licdbapi
 
#testdbapi:testdbapi.o  
#	$(CC) $(LIBFLAG) $^ -o $@ -lpthread  -lclntsh  -licdbapi
		
%.o:%.c
	$(CC) $(CFLGS) -c $< -o $@	

clean:
	rm -f *.o $(BIN)
	
	
	




