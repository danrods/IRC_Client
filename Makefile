CC = clang
CFLAGS = -Wall -Werror -Wextra -g 
SpecialFlags = -DDEBUGFLAG -DVERBOSEFLAG

Gui_Flag = -DGUIACTIVE

gui_args = `pkg-config --cflags gtk+-3.0` -o gtkGUI gtkGUI.c `pkg-config --libs gtk+-3.0`

# JasonTest = -DDJTEST
#-VERBOSEFLAG

BIN_SERV = server
BIN_CLI = client
SRC = $(wildcard *.c)
ADDI_O = helperMethods.o signals.o
OCLI_FILE = $(wildcard *~ *client.o) $(ADDI_O)
OSERV_FILE = $(wildcard *~ *server.o) $(ADDI_O)

user = James
server_flags = -e -s
client_flags = -c -s
port = 1824
ServerArgs = $(server_flags) $(port) "Welcome to the thunderdome"

#otherIP = 130.245.68.51

myIP = 0.0.0.0

ClientArgs =  $(client_flags) $(user) $(myIP) $(otherIP) $(port)

all: boilerPlate
 
allServer: all runServ

allClient: all runClient

boilerPlate: clean build link

build: $(SRC) 
	$(CC) $(CFLAGS) $(SpecialFlags) $(Gui_Flag) $(JasonTest) -c $^ 

clean:
	rm -f *~ *.o $(BIN_SERV) $(BIN_CLI)


debugServer: all gdbServer

debugClient: all gdbClient


link: linkServer linkClient

linkServer:
	$(CC) -o $(BIN_SERV) $(OSERV_FILE) -lssl -lcrypto -lpthread -lrt -lsqlite3

linkClient:
	$(CC) -o $(BIN_CLI) $(OCLI_FILE) -lrt -lpthread -lsqlite3

runServ: 
	./$(BIN_SERV) $(ShellFlags) $(ServerArgs)

runClient: 
	./$(BIN_CLI) $(ShellFlags) $(ClientArgs)

gdbServer:
	gdb -tui $(BIN_SERV)

gdbClient:
	gdb -tui $(BIN_CLI)

gui:
	gcc `pkg-config --cflags gtk+-3.0` -o gtkGUI gtkGUI.c `pkg-config --libs gtk+-3.0`
rungui:
	./gtkGUI

