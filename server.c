#include "aloha.h"


uNodeP userList[MAX_ARRAY_SIZE];
uNodeP FDList[MAX_ARRAY_SIZE];
//PollFD descriptors[MAX_CONN];
ePollEvent descriptors[MAX_CONN];

uNodeP allUsers = NULL; //TODO add users to this user List
chatNodeP chatrooms = NULL;
chatroomP waitingRoom = NULL;
echoP messageQueue = NULL;

int userListSize = MAX_ARRAY_SIZE;
int FDListSize = MAX_ARRAY_SIZE;

bool ECHO_MSG_ONSERVER = false;
bool echo_thread_created = false;
bool isSessionEnabled = false;
//bool DEBUG_OVERRIDE = false;

int totalChatrooms = 0; //Every chatroom ever made and closed
int totalUsers = 0; //Every User ever made
int userCount = 0;
int fdCount = 0;
int eFD = -1;

size_t chatroomCount = 0; //Currently how many chatrooms
size_t MAX_CHATROOMS = 5;

sem_t echoMutex;
sem_t userMutex;
sem_t fdMutex;

char* PORT_NUMBER;
char* MOTD;

int totalThreads = 0;
static pthread_t threads[3]; //Total Number of threads
size_t SESSION_SIZE =  5 * MAX_SALT;



char* ERROR_LIST[] = {"00 SORRY %s",
                            "01 USER %s EXISTS", 
                            "02 %s DOES NOT EXIST", 
                            "10 ROOM EXISTS", 
                            "11 MAXIMUM ROOMS REACHED",//5
                            "20 ROOM DOES NOT EXIST",
                            "30 USER NOT PRESENT",
                            "40 NOT OWNER",
                            "41 INVALID USER",
                            "60 INVALID OPERATION",//10
                            "61 INVALID PASSWORD",
                            "100 INTERNAL SERVER ERROR",
                            "404 INVALID SESSION"};

char* GENERIC_SERVER_MSG[] = { "%s has been kicked out.",
								"%s has left the room.",
								"%s has been promoted to owner",
								"%s has joined the room.",
								"New Chat room : %s was added."
							};


int main(int argc, char **argv){
	memset(&userList, 0, MAX_ARRAY_SIZE);
	memset(&FDList, 0, MAX_ARRAY_SIZE);
	memset(&descriptors, 0, sizeof(ePollEvent) * MAX_CONN);
	//descriptors = Calloc(MAX_CONN, sizeof(PollFD));

	
	chatDataP data;
	if((! (data = CreateChatRoom(NULL, "Waiting Room"))) || (data->isError)){
		error("Waiting room is null!\n");
		exit(EXIT_FAILURE);
	}
	else{
		waitingRoom = data->newRoom;
		FreeChatData(data);
	}
	//addChatroom(waitingRoom);

	if(! (start320(&echoMutex,TOTAL_ECHO_THREADS))){
		error("Error initializing echo semaphore!\n");
		exit(EXIT_FAILURE);
	}

	if(! (start320(&userMutex,TOTAL_USER_THREADS))){
		error("Error initializing user semaphore!\n");
		exit(EXIT_FAILURE);
	}

	if(! (start320(&fdMutex, TOTAL_FD_THREADS))){
		error("Error initializing FD semaphore!\n");
		exit(EXIT_FAILURE);
	}
	
	SignalFunc(SIG_PIPE, SIG_IGN); //Ignore SigPipes sucka
	SignalFunc(SIG_HUP, signal_interrupt);
	SignalFunc(SIG_QUIT, signal_interrupt);
	SignalFunc(SIG_TERM, signal_interrupt);
	SignalFunc(SIG_STOP, signal_interrupt);
	SignalFunc(SIG_TSTP, signal_interrupt);


	parse_options(argc, argv);

	//addFD(STDIN_FILENO);

	/*if(InitializeDatabase()){
		std_error("Error intializing Database, Data will not be persistent!\n");
	}
	else{
		reloadUsers();
	}*/

	initiateListener();
	EPollInputFDs();

	//PollInputFDs();
/*
	if(argc)argv++;

	char* name = malloc(100);
	strcpy(name, "IAMNEW jfontaine");
	// userP newUser = Calloc(1, sizeof(User));
	// newUser -> fd = 4;
	// newUser -> name = name;
	

	parseInput(4, name);
	parseInput(4, name);

*/
	//free(echoMutex);
	//free(userMutex);
	//free(fdMutex);
	FreeChatroom(waitingRoom);


}


void parse_options(int argc, char** argv){
    int opt;

    while((opt = getopt(argc, argv, "heNs")) != -1) {
        switch(opt) {
            case 'h':
                  debug("-h has been added \n");	
                  SERVER_USAGE(argv[0]);
                  exit(EXIT_OK);
                  break;
            case 'e':
                  debug("-e has been added \n");
                  ECHO_MSG_ONSERVER = true;
                  break;
            case 's':
                  debug("-s has been added \n");
                  isSessionEnabled = true;
                  break;
            case 'N':
            	  debug("-N has been added with Max Chatrooms : %s\n", optarg);
            	  if(! optarg) exit(EXIT_FAILURE);
            	  MAX_CHATROOMS = atoi(optarg);
            	  break;
            case '?':
                  debug("Passed value -> ?\n");
                  debug("Option Argument : %s\n",optarg);
            default:
                break;
        }
    }

    if(optind < argc && (argc - optind) == 2) { /*Check to see if there are arguments not corresponding to tacks*/
        debug("Found Port : %s\n", argv[optind]);
        PORT_NUMBER = argv[optind++];
        debug("Assigning MOTD : %s\n", argv[optind]);
        MOTD = argv[optind];
    } 
    else{
    	std_error("Could not find PORT and/or MOTD -- Exiting!\n");
    	SERVER_USAGE(argv[0]);
    	exit(EXIT_FAILURE);
    }

}



/******************* Connection **********************/

void initiateListener(){

	struct addrinfo hints, *conns = NULL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;	
	hints.ai_flags= SERVER_AI_FLAGS;
	getaddrinfo(NULL, PORT_NUMBER, &hints, &conns);

	int* listenFD = Calloc(1, sizeof(int));
	if((*listenFD= server_fetchBindListenSocket(conns)) < 0){
		error("There was a problem binding the socket\n");
		exit(EXIT_FAILURE);
	}

	pthread_t thread;
	thread = Create_Thread(&thread, NULL, server_Listen,listenFD);
	threads[totalThreads++] = thread;

}

void EPollInputFDs(){
	int events;

	
	eFD = CreateEPoll(0);
	addEPollFD(STDIN_FILENO);
	ePollP pollEvents = calloc(MAX_EVENTS, sizeof(ePollEvent));
	output("Currently Listening on Port %s\n", PORT_NUMBER);
	while(true && !stop_signal){

repeat:
		events = EPollWait(pollEvents, MAX_EVENTS);
		//printDescriptor(descriptors, fdCount);

		if(events == 0){ //Timed out, none ready
			//error("Timeout, all quiet on the western front!\n");
		}
		else if(events < 0){ //Error!
		 	error("There was a problem polling for FD's %d ---> %s\n", errno, strerror(errno));
		}
		else{

			char buffer[MAX_LINE];
			memset(&buffer,0,MAX_LINE);

			//for(int i = 0; i < fdCount; i++){
			for(int i = 0 ; i < events; i++){

				int fd = pollEvents[i].data.fd;
				uint32_t newEvent = pollEvents[i].events;
				//ePollP desc = (descriptors + i);
				//debug("New Event! : %x\n", newEvent);

				if ((newEvent & EPOLLERR) || ( newEvent & EPOLLHUP) || (!(newEvent & EPOLLIN)) || (newEvent & EPOLLRDHUP)
				 || (!newEvent & EPOLLOUT))
			    {

			        //An error has occured on this fd, or the socket is notready for reading 
				    error("Hanging Up %d!\n", fd);

				    //////////////SEND BYE/////////////////
					Bye(fd, getUserFD(fd)); // Do some user cleanup and then remove the FD from HASH
					/////////////////////////////////////
					removePoll_fd(fd); //Remove user from the polling FD's
				    ////////////////////////////////////

				    Close (fd);
				    
				    continue;
			    }
			    else if(fd == STDIN_FILENO){
			    	//READ from Stdin

					if(newEvent & EPOLLIN){
						char* str = fgets(buffer, MAX_LINE, stdin);
						//int count = ReadBuffer(STDIN_FILENO, buffer);
						debug("Read %s from the user on FD %d\n", str, fd);

						str = trim(str);

						//debug("Trimmed string to %s|\n", str);
						//desc->revents = 0;
						DEBUG_OVERRIDE = true;
						if(strstr(str, "/echo")){
							printMessageQueue(messageQueue);
						}
						else if (strstr(str, "/chats")){
							printChatrooms(chatrooms);
						}
						else if(strstr(str, "/users")){
							printUserList(allUsers);
						}
						else if(strstr(str, "/progress")){
							get320ProgressReport();
						}
						else if(strstr(str, "/descriptor")){
							printDescriptor(descriptors, fdCount);
						}
						else if(strstr(str, "/sessions")){
							printSessionList(allUsers);
						}
						else{
							debug("Je ne sais Pas!\n");
						}

						DEBUG_OVERRIDE = false;

					}
				
			    }

				else
				{//There was a data event
 
						int bytes;
					
						if((bytes = recv(fd, buffer,MAX_LINE,0)) > 0){
							debug("Read String %s from the user!\n", buffer);

							//char* end = buffer;

							char* token = strtok2_O(buffer, CR_LF);

							if(token){ //If we found 1
								//debug("\n------------------------------------------\n");
								if(! parseInput(fd, token)){
									//error("There was a problem parsing input!\n");
								}
								//debug("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
								while((token = strtok2_O(NULL,CR_LF))){ //Keep going until we hav all of them
								//	debug("\n------------------------------------------\n");
									if(! parseInput(fd, token)){
											//error("There was a problem parsing input!\n");
									}
								//	debug("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
								}
							}

							debug("Done parsing!\n");


							
						}
						else if(bytes == 0){
							//////////////SEND BYE/////////////////
							Bye(fd, getUserFD(fd)); // Do some user cleanup and then remove the FD from HASH
							/////////////////////////////////////
							removePoll_fd(fd); //Remove user from the polling FD's
						}
						else{


							error("There was a problem Receiving data on FD :%d  {%d ---> %s}\n", fd, errno, strerror(errno));						

							bool isError = false;
							if(errno ==  EPIPE){
								isError = true;
								debug("There was a hangup on the other end!\n");
							}
							else if(errno == ECONNRESET){
								isError = true;
								debug("Connection reset!\n");
							}
							else if(errno == ECONNREFUSED){
								isError = true;
								debug("Connection Refused!\n");
							}
							else if(errno == EINVAL){
								isError = true;
								debug("Invalid Argument!!\n");
							}
							else if(errno == EINTR){
								debug("Trying again!\n");
								goto repeat;
							}
							else{
								debug("I have no idea!\n");
							}

							
							
							//debug("Checking FD %d\n", desc->fd);
							if(isError){

								//error("There was a problem Receiving data on FD :%d  {%d ---> %s}\n", fd, errno, strerror(errno));
							
								

							}
							
							
						}
					

					//debug("Events left : %d!\n", events--);
					//if(events == 0) break; //If we've handled all the events then we're done
				}// END (Else)
			}//END FOR
			debug("Finished Looping events!\n");
		}//End (Else)
	}//End (While)



}

/*
void PollInputFDs(){
	int events;

	while(true && !stop_signal){
		events = poll(descriptors,fdCount, POLL_TIMEOUT);
		//printDescriptor(descriptors, fdCount);

		if(events == 0){ //Timed out, none ready
			//error("Timeout, all quiet on the western front!\n");
		}
		else if(events < 0){ //Error!
			//error("There was a problem polling for FD's %d ---> %s\n", errno, strerror(errno));
		}
		else{

			char buffer[MAX_LINE];
			memset(&buffer,0,MAX_LINE);

			for(int i = 0; i < fdCount; i++){
				pollP desc = (descriptors + i);

				if(i == 0)
				{ //READ from Stdin

					if((desc->revents) & POLLIN){
						char* str = fgets(buffer, MAX_LINE, stdin);
						//int count = ReadBuffer(STDIN_FILENO, buffer);
						debug("Read %s from the user on FD %d\n", str, desc->fd);

						str = trim(str);

						//debug("Trimmed string to %s|\n", str);
						desc->revents = 0;

						if(strstr(str, "/echo")){
							printMessageQueue(messageQueue);
						}
						else if (strstr(str, "/chats")){
							printChatrooms(chatrooms);
						}
						else if(strstr(str, "/users")){
							printUserList(allUsers);
						}
						else if(strstr(str, "/progress")){
							get320ProgressReport();
						}
						else if(strstr(str, "/descriptor")){
							printDescriptor(descriptors, fdCount);
						}
						else if(strstr(str, "/sessions")){
							printSessionList(allUsers);
						}
						else{
							debug("Je ne sais Pas!\n");
						}

					}
					
					
				}
				else if((desc)-> revents & POLLIN)
				{//There was a data event

					int bytes;
					if((bytes = recv(desc->fd,buffer,MAX_LINE,0)) > 0){
						debug("Read String %s from the user!\n", buffer);

						//char* end = buffer;

						char* token = strtok2_O(buffer, CR_LF);

						if(token){ //If we found 1
							//debug("\n------------------------------------------\n");
							if(! parseInput(desc->fd, token)){
								//error("There was a problem parsing input!\n");
							}
							//debug("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
							while((token = strtok2_O(NULL,CR_LF))){ //Keep going until we hav all of them
							//	debug("\n------------------------------------------\n");
								if(! parseInput(desc->fd, token)){
										//error("There was a problem parsing input!\n");
								}
							//	debug("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
							}
						}

						debug("Done parsing!\n");


						
					}//Recv
					else
					{
						bool isError = true;
						if(desc->revents & POLLHUP){
							debug("There was a hangup on the other end!\n");
						}
						else if(desc->revents & POLLNVAL){
							debug("Invalid Request, FD not open!\n");
						}
						else if(desc->revents & POLLERR){
							debug("There was an error!\n");
						}
						else if(desc->revents & POLLIN){
							isError = false;
							//debug("Data to read!\n");
						}
						else if(desc->revents & POLLOUT){
							isError = false;
							debug("Out of bound Data to read!\n");
						}
						else if(desc->revents & POLLRDHUP){
							debug("Stream socket peer closed connection!!\n");
						}
						else{
							debug("I have no idea!\n");
						}

						
						
						//debug("Checking FD %d\n", desc->fd);
						if(isError){

							error("There was a problem Receiving data on FD :%d  {%d ---> %s}\n", desc->fd, errno, strerror(errno));
						
							//////////////SEND BYE/////////////////
							Bye(desc->fd, getUserFD(desc->fd)); // Do some user cleanup and then remove the FD from HASH
							/////////////////////////////////////
							removePoll_fd(desc->fd); //Remove user from the polling FD's

						}
						
						desc->revents = 0;
					}
					//debug("Events left : %d!\n", events--);
					if(events == 0) break; //If we've handled all the events then we're done
				}// END (Else if)
			}//END FOR
		}//End (Else)
	}//End (While)

}
*/

void* server_Listen(void* fd){
	/////BoilerPlate//////
	int listenFD = *(int*) fd;
	Detach_Thread(this());
	free(fd);
	//////////////////////

	int newConn;

	connP connection;
	SocketLength length;
	struct sockaddr_storage * clientAddress;
	

	while(true && ! stop_signal){

		clientAddress = Calloc(1, sizeof(struct sockaddr_storage));
		length = sizeof(struct sockaddr_storage);
		connection = createConnP((Socket)clientAddress);

		newConn = server_AcceptConnection(listenFD, (Socket)clientAddress, &length);
		connection->length = length;
		connection->fd = newConn;
		
		debug("Accepted Connection, creating thread to bind the connection!\n");
		pthread_t thread;
		Create_Thread(&thread, NULL, createConnection,connection);
		
//char* inputBuf = malloc(MAX_INPT);
	//memset(inputBuf,0, MAX_INPT);
	//count = ReadBuffer(listenFD,inputBuf);
	}

	
	return NULL;
}

void* createConnection(void* ptr){
		struct sockaddr_storage clientAddress;
		char host[MAX_LINE], port[MAX_LINE];

		 /////BoilerPlate//////
		connP conn = (connP) ptr;
		Detach_Thread(this());
		int fd = conn-> fd;
		memcpy(&clientAddress, conn->connAddr, conn->length);
		int length = conn->length;
		FreeConnection(conn);
		//////////////////////
		

		if(! (getnameinfo((Socket) &clientAddress, length, host, MAX_LINE, port, MAX_LINE, 0))){
			debug("Client Connected with Host : %s \t port : %s\n", host, port);
		}
		else {
			error("Couldn't figure out connection info!\n");
		}


		if(fd > 0){
			//addFD(fd);
			addEPollFD(fd);
		}
		else{
			error("Could not accept new connection!\n");
		}


		
		if(! echo_thread_created){
			pthread_t thread;
			thread = Create_Thread(&thread, NULL, createEchoThread ,NULL);
		}

		//debug("Thread dying- Connection Complete!\n");
		return NULL;
}


void* createEchoThread(void*ptr){
		/////BoilerPlate//////
		echo_thread_created = true;
		Detach_Thread(this());
		ptr++;
		//////////////////////
		sigset_t mask, prev;
		SignalFunc(SIG_ALARM, sig_wake_echo);
		sigemptyset(&mask);
  		synchronizeFull(&mask, &prev);
  		//ePollP pollEvents = calloc(MAX_EVENTS, sizeof(ePollEvent));

		while(true && !stop_signal){

			
			//endSynchronize(&prev);

			if(! messageQueue){ //There are no messages!
				

				//debug("Nighty night!\n");
				while(echo_signal == 0) //Wait for alarm
					;//sleep(1);
     				//sigsuspend(&prev);
     			//debug("Wake up! time to do some work!\n");
     			
			}
			else{ //There's at least 1 message


				echoP next;
				//debug("Dequeuing a message!\n");
				while((next = dequeueMessage())){ //While there are new messages

					verbose("DEQUEUE");

					debug("Dequeued Message %s\n", next->message);
					uNodeP start, head; 

					debug("Users There? %d\n", (int)next->users);
					start = head = next -> users;

					printUserList(next->users);

					//debug("Sending Message : %s\n", next->message);

					if(! start){
						error("There are no users assigned to the message %s\n", next->message);
						break;
					}

					if(! next->isPrivate && ECHO_MSG_ONSERVER){

						//printPromptUser(next->message, start->user->name, next->message);
						//debug("Sending Message : ---> %s\n", next->message);
						char* response = next -> message;
						char* divider = strstr(response, " ");

						char* msg = divider + 1; //EVerything after the VERB
						char* space = strstr(msg, " "); //Seprate the sender and the msg
						*(space) = '>';
						output("%s\n", msg);
						*(space) = ' ';
					}


					do
					{	

						int index;//, events ;
						if((index = findFDIndex((start-> user-> fd))) < 0){
							error("Couldn't find FD %d in the list of descriptors\n", start->user->fd);
						}
						else
						{ //Index was found, it exists!
							/*
							int counter = 5; //Try 5 times to wait for the user to be ready
							int events;
							while((events = EPollWait(pollEvents,  MAX_EVENTS)) <= 0){
								if(counter-- == 0){
									error("User is unreachable!\n");
									removeEPollFD(index);
									removeUser(start->user->fd);
									break;
								}
							}

							if(counter){ //We tried 5 times and got nowhere
							*/


								verbose("Sending Message!");


								debug("Print to user %s\n", start->user->name);


								/*
								if(isSessionEnabled && start->user->session && ! strstr(SESSION_PREFIX)){
									debug("Session Adding!\n");
									char* oldMsg = next-> message;
									char * newMsg = buildEchoString(next->message, start->user->session);
									next->message = newMsg;
									free(oldMsg);
									debug("Session Adding Done!");
								}
								else{
									debug("Sessions Disabled or problem with Session ID : %s\n", start->user->session);
								}
										*/
								

								char* msg = Build_Color_Message(OUTPUT_COLOR,next -> message);
								debug("Sending Message %s \nto file descriptor %d\n", msg, (descriptors + index)->data.fd);
								free(msg);
								errno = 0;

								Send(start->user->fd, next->message);
								//verbose("Successfully sent Message!");

								if(errno){
									debug("Some kind of error! {%d --> %s}\n", errno, strerror(errno));
									verbose("END Sending Message --> Fail");
								}
								else{
									verbose("END Sending Message --> Success");
								}

								
								
							//}
							/*}
							else{
								error("Nope\n");
							}*/
						}
						start = start->next;
					}while(start && start != head);

					
					FreeEcho(next);

					verbose("END DEQUEUE");

				}//END Dequeue message

				debug("Done with messages!\n");
				echo_signal = 0;
				//goOnVacation(echoMutex);
			}

		}

		debug("Dying! C'est la vie!\n");
		return NULL;
}


int server_AcceptConnection(int fd, Socket socket, SocketLenP length){
	int returnValue;


    if ((returnValue = accept(fd, socket, length)) < 0){
		error("There was an error accepting the connection!\n");
    }
    return returnValue;
}


/******************* END Connection ******************/




/******************** PARSING ***********************/

bool parseInput(int fd, char * input){//TODO : input should be MALLOC'd
	char* delim = " ";

	verbose("Parse Input %s", input);
	if(! input || strlen(input) == 0){
		error("Invalid input from User!\n");
		return false;
	}


	char* msg = Build_Color_Message(ARG_COLOR,input);
	debug("Parsing Input %s\n", msg);
	free(msg);

	char* inputCopy = copyString(input);

	char* token = strtok(inputCopy, delim);
	debug("Found token %s\n", token);
	char * arguments = inputCopy + strlen(token) + 1; //The 1 will put us past the \0
	debug("Arguments : %s\n", arguments);

	if(! token){
		return FreeInputAndReturn(inputCopy, false);
	}

	//char* arguments = copyString(rest);

	
	userP tempUser;

	if(! strcmp(token, INTRO_CLIENT)){
		verbose("ALOHA!");
		uNodeP node = createTempUserAndNode(fd);
		createPrivateEchoAndEnqueue(INTRO_SERVER, NULL, node);
		verbose("END ALOHA!");
		return FreeInputAndReturn(inputCopy, true);

	}
	else if(! strcmp(token, LOGIN)){
		
		verbose("Login!");

		if((tempUser = loginStep1(fd, arguments))){
			if(tempUser -> isLoggedIn){
				error("User is already logged in!");
				uNodeP node = createTempNode(tempUser);
				char* buf = fill_error_str(ERROR_LIST[SORRY], arguments);
				//LogAuthenication Fail because user is logged in
				createPrivateEchoFreeAndEnqueue(ERROR, buf, node);
				createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node);
				return FreeInputAndReturn(inputCopy, false);
			} 
			tempUser -> isAuthenticating = true;

			debug("Creating temp node for user : %s\n", tempUser->name);
			uNodeP node = createTempNode(tempUser);
			createPrivateEchoAndEnqueue(LOGIN_AUTH_ACK, arguments, node);

			verbose("END Login!");
			return FreeInputAndReturn(inputCopy, true);
		}
		else{
			uNodeP node1 = createTempUserAndNode(fd);
			uNodeP node2 = createTempUserAndNode(fd);
			//LogAuthenication with Sorry
			char* buf = fill_error_str(ERROR_LIST[SORRY], arguments);
			createPrivateEchoFreeAndEnqueue(ERROR, buf, node1);
			createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node2);
			//free(buf);
			verbose("END Login!\n");
			return FreeInputAndReturn(inputCopy, false);
		}

		
	}
	else if(! strcmp(token,CREATE_USER)){

		verbose("Create User!");

		if((tempUser = createUser(fd, arguments)))
		{
			debug("Created user Successfully!\n");

			uNodeP node = createTempNode(tempUser);
			debug("Created the temp node!\n");

			createPrivateEchoAndEnqueue(CREATE_USER_ACK, arguments, node);
			debug("Created the echo!!\n");

			tempUser -> isAuthenticating = true;
			InsertUser(tempUser);
			verbose("END Create User!");
			return FreeInputAndReturn(inputCopy, true);
		}
		else
		{
			debug("Error creating the user!");
			uNodeP node1 = createTempUserAndNode(fd);
			uNodeP node2 = createTempUserAndNode(fd);
			//LogAuthenication with Sorry
			char* buf = fill_error_str(ERROR_LIST[SORRY], arguments);
			createPrivateEchoAndEnqueue(ERROR, buf, node1);
			createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node2);
			//free(buf);

			verbose("END Create User!");
			return FreeInputAndReturn(inputCopy, false);
		}
	}

	debug("Finding user!\n");
	userP user;

	if(! (user = getUserFD(fd))){
		error("User not found for FD : %d\n", fd);
		return FreeInputAndReturn(inputCopy, false);
	}
	
	debug("Found the user! %s\n", user->name);
	printUser(user);

	uNodeP node = createTempNode(user);

	debug("Created temp user!\n");




	if(user -> isAuthenticating){



			if(! strcmp(token, PASSWORD)){

				verbose("Auth Password!");

				if(loginComplete(fd, arguments)){

					user -> isAuthenticating = false;
					user -> isLoggedIn = true;
					//LogAuthenication	
				}
				else{
					//LogAuthenication Password
					createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[PASSWORD_NO], node);
					createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node);
					return FreeInputAndReturn(inputCopy, false);
				}

				verbose("END Auth!");
			}
			else if(! strcmp(token, CREATE_PASS)){

				verbose("Creating PASSword!");

				if(addPassword(fd, arguments)){
					user -> isAuthenticating = false;
					user -> isLoggedIn = true;
					//LogAuthenication User is logged
				}
				else{

					if(Bye(fd, user)){
						error("There was a problem leaving!\n");
					}
					//LogAuthenication
					createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[PASSWORD_NO], node);
					createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node);
					return FreeInputAndReturn(inputCopy, false);
				}
				verbose("END Password!");


				if(user-> isLoggedIn){
					uNodeP newUser = createUserNode(user);
					nodeDataP data = addUserNode(allUsers, newUser);
					
					if(data->isError){
						error("There was a problem adding users to global list!\n");
						//LogAuthenication Default
						createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
						createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node);
						return FreeInputAndReturn(inputCopy, false);
					}
					else{
						allUsers = data -> headOfList;
					}

				}
				else{
					error("User is not logged in, can't continue");
					user->isAuthenticating = false;
					//LogAuthenication
					createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
					createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node);
					return FreeInputAndReturn(inputCopy, false);
				}
			}


		/*** Log in successful*****/

		char* motd = buildEchoString(SERVER, MOTD);
		createPrivateEchoFreeAndEnqueue(ECHO_CMD, motd, node);


		if(isSessionEnabled){
			user -> session = generateRandomSession(SESSION_ALPHABET, SESSION_SIZE);
			char* ack = buildEchoString(user->name, user->session);
			createPrivateEchoFreeAndEnqueue(LOGIN_COMPLETE_ACK, ack, node);
		}
		else{
			createPrivateEchoAndEnqueue(LOGIN_COMPLETE_ACK, user->name, node);
		}

		/**************************/


		return FreeInputAndReturn(inputCopy, true);

	
	}
	else if(! user->isLoggedIn){
		error("User is not logged in, can't continue");
		createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
		createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, node);
		return FreeInputAndReturn(inputCopy, false);
	}
	else{
		debug("User is Logged in!\n");
	}





	


	




	/************ Successfully Logged in and able to take messages at this point!************/



	if(isSessionEnabled){ //SESSION VALIDATION
		char* session = findSession(arguments);

		if(! session){
			error("User Session Not found in response!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(! strcmp(session, user->session)){
			debug("Found Session! --> Continuing!");
		}
		else{
			error("User session MISMATCH --> FAIL");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[SESSION_INVALID], node);
			return FreeInputAndReturn(inputCopy, false);
		}

		if(*(session -1) == ' ') *(session -1)='\0';
	}





	if(! strcmp(token , SEND_MSG)){
		verbose("SEND MSG");

		if(user->room == waitingRoom){
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
			return FreeInputAndReturn(inputCopy, false);
		}
		else
		{
			createEchoCmdAndEnqueue(user->name, arguments, user->room->users);
		
		}

		

		verbose("END SEND MSG");
	}
	else if(! strcmp(token, CREATER_VERB)){

		verbose("Start Chatroom!");

		if(chatroomCount >= MAX_CHATROOMS){
				verbose("END Chatroom -- >Maximum Chatrooms!");

				createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[MAX_ROOM], node);

				return FreeInputAndReturn(inputCopy, false);
		}
		else if(user->room != waitingRoom){
			verbose("END Chatroom -- >User is not in Waiting Room!");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
			return FreeInputAndReturn(inputCopy, false);
		}



		chatDataP returnVal = CreateRoom(user, arguments, NULL);

		if(! returnVal){//Duplicate
				verbose("Problem creating a room!");
				createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[ROOM_DUP], node);
				return FreeInputAndReturn(inputCopy, false);
		}
		else{

			switch(returnVal->isError){

			case 0:
				verbose("Room was created!!");
				if(! returnVal->newRoom || ! addChatroom(returnVal->newRoom)){
					error("There was a problem adding the chatroom %s\n", returnVal->newRoom->name);
					createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
					return FreeInputAndReturn(inputCopy, false);	
				} 
				createPrivateEchoAndEnqueue(CREATE_ACK, arguments, node);
				fillStringCreateEchoCmdAndEnqueue(SERVER, GENERIC_SERVER_MSG[NEW_ROOM], arguments, user->room->users); //Echo to all users of kick
				break;
			case 1:
			default:
					error("Something done happened!\n");
					createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
					return FreeInputAndReturn(inputCopy, false);
				break;

			}

			FreeChatData(returnVal);
		}
		
	

		verbose("End Chatroom!");
	}
	else if(! strcmp(token, CREATER_PRIVATE_VERB)){
		verbose("Create Private Room!");

		if(chatroomCount >= MAX_CHATROOMS){
				verbose("END Create Private Room -- >Maximum Chatrooms!");
				createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[MAX_ROOM], node);
				return FreeInputAndReturn(inputCopy, false);
		}
		else if(user->room != waitingRoom){
			verbose("END Create Private Room -- >User is not in Waiting Room!");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
			return FreeInputAndReturn(inputCopy, false);
		}

		char* usrname = strtok(arguments, delim);
		char* password = usrname + strlen(usrname) + 1;


		chatDataP returnVal = CreateRoom(user, usrname, password);


		if(! returnVal){//Duplicate
				verbose("Problem creating a room!");
				createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[ROOM_DUP], node);
				return FreeInputAndReturn(inputCopy, false);
		}
		else{

			switch(returnVal->isError){

			case 0:
				verbose("Room was created!!");
				createPrivateEchoAndEnqueue(CREATE_PRIVATE_ACK, usrname, node);
				fillStringCreateEchoCmdAndEnqueue(SERVER, GENERIC_SERVER_MSG[NEW_ROOM], arguments, user->room->users); //Echo to all users of kick
				break;
			case 2: //Invalid password
				createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[PASSWORD_NO], node);
				FreeChatData(returnVal);
				return FreeInputAndReturn(inputCopy, false);
			case 1://Couldnt create
			case 3://error associating password
			case 4://error adding chatroom to global list
			default:
				createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
				FreeChatData(returnVal);
				return FreeInputAndReturn(inputCopy, false);

			}

			FreeChatData(returnVal);
		
		}


		verbose("END Create Private Room!");

	}
	else if(! strcmp(token, CLOSE_CONN)){

		verbose("BYE");

		userP copy = copyUser(user);

		if(Bye(fd, user)){
			uNodeP nodeCopy = createTempNode(copy);
			createPrivateEchoAndEnqueue(CLOSE_CONN, NULL, nodeCopy);
		}
		else{
			free(copy);
			error("Problem closing the connection!\n");
			echoP echo = createPrivateEcho(ERROR, ERROR_LIST[DEFAULT_ERR]);
			echo -> users = node;
			enqueueMessage(echo);
			verbose("END BYE --> FAIL : Problem closing connection!");
			return FreeInputAndReturn(inputCopy, false);
		}

		verbose("END BYE --> Success!");
	}
	else if(! strcmp(token, KICK_VERB)){

		verbose("KICK!");

		userP kicked = getUser(arguments);
		int val;


		

		if(! kicked){
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[USER_NO], node);
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(! (val = kick(user, kicked))){
			uNodeP kickNode = createTempNode(kicked);
			int oldRoom = kicked -> room-> id;

			createPrivateEchoAndEnqueue(KICK_ACK, arguments, node);	// Send KCIK to user
			createPrivateEchoAndEnqueue(CLIENT_KICK_MSG, NULL, kickNode); //Send KBYE to kicked user

			if((findRoom(oldRoom))){//If room found, means still have people to send to!
				fillStringCreateEchoCmdAndEnqueue(SERVER, GENERIC_SERVER_MSG[KICKED], kicked->name, user->room->users); //Echo to all users of kick
			}

		}
		else if(val == 1){
			error("User is not in the same room!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
			verbose("END KICK --> User not in the room!");
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(val == 2){
			error("User is not admin!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[NOT_ALLOW], node);
			verbose("END KICK --> User is not admin!");
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(val == 3){
			error("Problem Kicking the user from the room!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
			verbose("END KICK --> ERR!");
			return FreeInputAndReturn(inputCopy, false);
		}

		verbose("END KICK --> Success!");
	}
	else if (! strcmp(token, LEAVE_VERB)){

		verbose("LEAVE Chatroom");


		chatroomP oldRoom = user->room;
		int oldID = oldRoom->id;

		printChatroom(oldRoom);

		if(user->room == waitingRoom){

			error("User is not in a room!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[USER_NOT_PRESENT], node);

			verbose("END LEAVE Chatroom --> User is in waiting room!");
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(Leave(user)){
			createPrivateEchoAndEnqueue(LEAVE_ACK, NULL, node);

			if((findRoom(oldID))){//If room found, means still have people to send to!
				fillStringCreateEchoCmdAndEnqueue(SERVER, GENERIC_SERVER_MSG[LEFT], user->name, oldRoom->users);
			}
			
		}
		else{
			error("Problem leaving the chatroom!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[USER_NO], node);
			verbose("END LEAVE Chatroom --> Problem leaving!");
			return FreeInputAndReturn(inputCopy, false);
		}

		verbose("END LEAVE Chatroom --> Success!");
	}
	else if(! strcmp(token, TELL_VERB)){

		verbose("TELL");

		uNodeP privateUser;
		char* toUsrname = strtok(arguments, delim);
		char* message = toUsrname + strlen(toUsrname) + 1;

		debug("Checking Username : %s and Message : %s\n", toUsrname, message);

		if(! toUsrname || ! message){
			verbose("END TELL --> FAIL : No username/message");
			return FreeInputAndReturn(inputCopy, false);
		}

		if((privateUser = MsgPrivate(user, toUsrname))){

			*(message - 1) = ' ';

			uNodeP temp = createTempNode(privateUser->user);
			char* buf = buildEchoString(user->name, message);
			//createPrivateEchoAndEnqueue(ECHO_CMD, buf, node);

			char* buf2 = buildEchoString(user->name, message);
			//createPrivateEchoAndEnqueue(ECHO_CMD, buf, node);

			createPrivateEchoAndEnqueue(TELL_ACK, buf, node);
			createPrivateEchoAndEnqueue(TELL_CLIENT_PREFIX, buf2, temp);

			free(buf);
			free(buf2);

		}
		else{
			error("Problem Messaging the user!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[USER_NOT_PRESENT], node);

			verbose("END TELL! ---> Problem Messaging!");
			return FreeInputAndReturn(inputCopy, false);
		}

		verbose("END TELL! ---> Success!");
	}
	else if(! strcmp(token, JOIN_VERB)){

		verbose("JOIN");

		int id = atoi(arguments);

		chatNodeP cnode = findRoom(id);

		if(cnode && cnode->room->password){//Its a private room
			error("User can't join private room from Join!");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(! (user->room == waitingRoom)){
			error("User is already in a room!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
			verbose("END JOIN --> User in the waiting room!");
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(JoinRoom(user, id)){
			debug("Joined the room %d!\n", id);
			createPrivateEchoAndEnqueue(JOIN_ACK, arguments, node);
			fillStringCreateEchoCmdAndEnqueue(SERVER, GENERIC_SERVER_MSG[JOINED], user->name, user->room->users);
		}
		else{
			error("Room doesn't exist!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[ROOM_NF], node);
			verbose("END JOIN --> Room Doesnt exist!");
			return FreeInputAndReturn(inputCopy, false);
		}

		verbose("END JOIN --> Success");
	}
	else if(! strcmp(token, JOIN_PRIVATE_VERB)){

		verbose("JOIN Private");

		char* usrname = strtok(arguments, delim);
		char* password = usrname + strlen(usrname) + 1;

		debug("Checking Username %s and password : %s\n", usrname, password);

		if((! usrname || strlen(usrname) ==0) || (! password || strlen(password) == 0)){
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
			return FreeInputAndReturn(inputCopy, false);
		}

		int id = atoi(usrname);

		int rv;

		if(! (user->room == waitingRoom)){
			error("User is already in a room!\n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
			verbose("END JOIN --> User in the waiting room!");
			return FreeInputAndReturn(inputCopy, false);
		}
		else if(! (rv = JoinPrivateRoom(user, id, password))){
			debug("Joined the room %d!\n", id);
			createPrivateEchoAndEnqueue(JOIN_PRIVATE_ACK, arguments, node);
			fillStringCreateEchoCmdAndEnqueue(SERVER, GENERIC_SERVER_MSG[JOINED], user->name, user->room->users);
		}
		else
		{
				switch(rv){

					case 1:
						error("Room doesn't exist!\n");
						createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[ROOM_NF], node);
						verbose("END JOIN Private --> Room doesn't exist");
						break;
					case 2:
						error("Invalid Password!\n");
						createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[PASSWORD_NO], node);
						verbose("END JOIN Private --> Invalid Password!");
						break;
					case 3:
						error("Problem adding user to room!\n");
						createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
						verbose("END JOIN Private --> Error adding user!");
						break;
					default:
						verbose("END JOIN Private --> Yeah you done messed up!");
						break;
				}
					return FreeInputAndReturn(inputCopy, false);

			}
			
		
		verbose("END JOIN Private --> Success");
	}
	else if(! strcmp(token, LISTROOM_VERB)){
		char* rooms;
		if((rooms = ListRooms())){
			debug("Listed rooms!\n");
			createPrivateEchoAndEnqueue(LISTROOM_ACK, rooms, node);
			//free(rooms);
		}
		else{
			error("Error listing the rooms! \n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[DEFAULT_ERR], node);
			return FreeInputAndReturn(inputCopy, false);
		}
	}
	else if(! strcmp(token, LIST_USERS_VERB)){
		char * users;
		if((users = ListUsers(user))){
			debug("Listed Users!\n");
			createPrivateEchoAndEnqueue(LIST_USER_ACK, users, node);
			//free(users);
		}
		else{
			error("Error listing the users! \n");
			createPrivateEchoAndEnqueue(ERROR, ERROR_LIST[OPERATION_NO], node);
			return FreeInputAndReturn(inputCopy, false);
		}
	}

	//free(input); //May need to free the space if it was malloc'd

	verbose("END - > Parse Input : Sucess!");
	return FreeInputAndReturn(inputCopy, true);
}





/******************** END PARSING ***********************/




/**************Hashing *********************/


ssize_t user_hash(char* message){
	size_t hashSum=0;

	if(! message || strlen(message) == 0){
		error("Can't hash an empty string");
		return -1;
	}

	char* msg = message;

	for(char c = *msg; *msg !='\0'; msg++)
		hashSum = hashSum + c;

	return hashSum % userListSize;
}

ssize_t fd_hash(int fd){
	if(fd < 0) return -1;
	return fd % FDListSize;
}

bool checkHash(ssize_t hash){
	if(hash < 0){
		error("Hash can't be negative");
		return false;
	}

	return true;
}

bool putUser(char* name, userP account){

	verbose("putUser!");

	ssize_t hash = user_hash(name);
	if(! checkHash(hash)){
		verbose("\tEND putUser : Failure --> error hashing");
		return false;
	}

	bool returnValue = true;
	uNodeP userNode = createUserNode(account);

	debug("Adding user Node!\n");
	nodeDataP returnVal = addUserNode(userList[hash], userNode);

	//printUserList(FDList[hash]);

	//debug("Printing userList");
	//printUserList(userList[hash]);

	if(returnVal -> isError) {
		error("There was a problem adding the user\n");
		free(userNode);
		returnValue = false;
	}
	else{
		userList[hash] = returnVal -> headOfList;
	}

	
	
	//debug("Printing Head of List");
	//printUserList(returnVal->headOfList);

	free(returnVal);

	if(++userCount > MAX_ARRAY_SIZE >> 1){ //If load factor > 0.5 do something
		error("Hash Array getting pretty big!\n"); //TODO : Do some rehashing I guess
	}

	verbose("END putUser! : Success!");

	return returnValue;
}

bool putUserFD(int fd, userP account){
	ssize_t hash = fd_hash(fd);
	if(! checkHash(hash)) return false;

	bool returnValue = true;
	uNodeP userNode = createUserNode(account);

	nodeDataP returnVal = addUserNode(FDList[hash], userNode);
	
	FDList[hash] = returnVal->headOfList;

	//debug("Printing FDLIST!\n");
	//printUserList(FDList[hash]);

	if(returnVal -> isError) {
		error("There was a problem adding the user\n");
		free(userNode);
		returnValue = false;
	}
	else{
		FDList[hash] = returnVal -> headOfList;
	}

	//debug("Printing head of list");
	//printUserList(returnVal->headOfList);

	free(returnVal);

	if(++userCount > MAX_ARRAY_SIZE >> 1){ //If load factor > 0.5 do something
		error("Hash Array getting pretty big!\n\n"); //TODO : Do some rehashing I guess
	}

	return returnValue;
}



void removeUser(int fd){
	userP user = getUserFD(fd);
	if(! user) return;

	debug("Removing User!\n");

	ssize_t hash_fd = fd_hash(fd);
	ssize_t hash_user = user_hash(user->name);
	if(! checkHash(hash_fd)) return;
	if(! checkHash(hash_user)) return;

	userList[hash_user] -> user -> fd = -1;
	userList[hash_user] -> user-> isAuthenticating = false;
	userList[hash_user] -> user-> isLoggedIn = false;

	nodeDataP node;
	node =  removeUserNode(FDList[hash_fd], user);

	if(node->isError){
		error("Error removing the user!\n");
	}
	else{
		--userCount;
		FDList[hash_fd] = node->headOfList;
	}
}

userP getUser(char* name){
	ssize_t hash_user = user_hash(name);
	if(! checkHash(hash_user)) return NULL;

	uNodeP start,head;
	start = head = userList[hash_user];

	if(! start) return NULL;

	do
    {	debug("Checking user : %s\n", start->user->name);
    	if(! strcmp(start->user->name, name)) return start->user;
    	start = start-> next;
    }while(start && start != head);

    return NULL;
}


userP getUserFD(int fd){

	ssize_t hash_fd = fd_hash(fd);
	if(! checkHash(hash_fd)) return NULL;
	uNodeP start,head;
	start = head = FDList[hash_fd];
	if(! start) return NULL;

	do
    {	debug("Start->User %d!\n", (int) start->user);
    	if(start->user->fd == fd) return start->user;
    	debug("There!\n");
    	start = start-> next;
    }while(start && start != head);

    return NULL;
}



nodeDataP addUserNode(uNodeP start, uNodeP node)
{	
	pass320(&userMutex, USER_SEM);

	nodeDataP returnValue = createAddUReturnNode(start);

	if(isDuplicateNode(start, node->user->name)){
		//error("Duplicate Node!\n");
		goOnVacation(&userMutex, USER_SEM);
		returnValue->isError = true;
		return returnValue;
	}

    if(start == NULL){ //None have been added
        returnValue->headOfList = start = node;
        start-> next = start->prev = node;
    }
    else if(start->prev == start){ //There's only one
        node-> next = node-> prev = start;
        start->next = start->prev = node;
    }
    else{ //At least 2
        uNodeP oldTail = start->prev; //Temporarily store the old tail
        oldTail-> next = node;
        node-> prev = oldTail; 
        node-> next = start;
        start-> prev = node;
    }
    goOnVacation(&userMutex, USER_SEM);

    //printUserList(start);
    return returnValue; 
}


nodeDataP removeUserNode(uNodeP head, userP user)
{
      uNodeP start = head;

      nodeDataP returnValue = createAddUReturnNode(start);

      if(! (start)){
      	error("Head of list is null!");
      	returnValue->isError = true;
      	return returnValue;
      }
      if(! user){
      	error("User Cannot be Null");
      	returnValue->isError = true;
      	return returnValue;
      }

      pass320(&userMutex, USER_SEM);

      //printUserList(head);

    do
    {
      if(start->user == user)
      {

	        if(start -> next == start) //There's only one
	        {
	              debug("Deleting Head %s\n",start->user->name);
	              returnValue->headOfList = NULL;   
	       }
	       else //2 or more
	       {
		          debug("Deleting user %s\n",user->name);
		          if(start == head){returnValue->headOfList = start->next;} //The head should be the next possible one
		          uNodeP nextOne = start->next;
		          start->prev->next = nextOne;
		          nextOne->prev = start->prev;
		          start-> next = start-> prev = NULL; //Remove all connections to it
	        }
	        //userCount--;
	        //free(start);
	        break;
      }

      start = start-> next;
    }while(start && start != head);

    goOnVacation(&userMutex, USER_SEM);
    //debug("Removed Node %s\n", start->user->name);
    // printProcess(returnProcess);
    return returnValue;

}




/**************END Hashing *********************/


bool addChatroom(chatroomP chatroom)
{	
	verbose("Add Chatroom!");
	chatNodeP start = chatrooms;

	if(! start){
		error("There are no chatrooms!");
	}

	chatNodeP node = createChatroomNode(chatroom);


    if(start == NULL){ //None have been added
    	debug("None!");
        chatrooms = start = node;
        start-> next = start->prev = node;
    }
    else if(start->prev == start){ //There's only one
    	debug("One!");
        node-> next = node-> prev = start;
        start->next = start->prev = node;
    }
    else{ //At least 2
    	debug("Many!");
        chatNodeP oldTail = start->prev; //Temporarily store the old tail
        oldTail-> next = node;
        node-> prev = oldTail; 
        node-> next = start;
        start-> prev = node;
    }

    verbose("END Add Chatroom! --> Success");
    chatroomCount++;
    return true;
}


void removeChatroomNode(chatroomP node)
{
	  verbose("RemovingChatroomNode!");
      chatNodeP start;
      start = chatrooms;
      if(! start) error("No chatrooms exist!");


    do
    {
      if(start->room == node)
      {

	        if(start -> next == start) //There's only one
	        {
	              debug("Deleting Head %s\n",start->room->name);
	              chatrooms = NULL;
	              
	       }
	       else //2 or more
	       {
		          debug("Deleting user %s\n",start->room->name);
		          if(start == chatrooms){chatrooms = start->next;} //The head should be the next possible one
		          chatNodeP nextOne = start->next;
		          start->prev->next = nextOne;
		          nextOne->prev = start->prev;
		          start-> next = start-> prev = NULL; //Remove all connections to it
	        }
	        //chatroomCount--;
	        //free(start);
	        break;
	        debug("Success!");
      }
      start = start-> next;
    }while(start && start != chatrooms);


    verbose("END RemovingChatroomNode!");
}

/*
bool addFD(int fd)
{	
	
	if(fdCount > MAX_CONN) return false;

	pass320(&fdMutex, FD_SEM);

	pollP poll = &*(descriptors + (fdCount++));
	poll->fd = fd;
	poll->events = POLLIN | POLLPRI ;
	poll->revents =  POLLHUP | POLLERR | POLLRDHUP | POLLNVAL;
	//debug("Successfully Added FD %d\n", fd);

    goOnVacation(&fdMutex, FD_SEM);
    return true;
   
}
*/
int findFDIndex(int fd){

	pass320(&fdMutex, FD_SEM);

	for(int i=0; i< fdCount; i++){
		//if((*(descriptors + i)).fd == fd){//Check FD of current iteration pollfd
		if((*(descriptors + i)).data.fd == fd){//Check FD of current iteration pollfd
			goOnVacation(&fdMutex, FD_SEM);
			return i;
		}
	}

	goOnVacation(&fdMutex, FD_SEM);
	return -1;
}

void removePoll_fd(int fd){
	verbose("Removing POLL FD!\n");
	int index;
	if((index = findFDIndex(fd)) < 0){
		error("No such FD exists! : %d\n", fd);
		return;
	}

	//removeFD(index);
	removeEPollFD(index);
	verbose("END - Removing POLL FD!-->Success!\n");
}

/*
void removeFD(int index)
{
	verbose("Remove FD! for Index %d", index);

	  int removedFD;

	  pass320(&fdMutex, FD_SEM);
	  printDescriptor(descriptors, fdCount);

      if(index < 0) error("No FD exist!\n");

      PollFD removeable = *(descriptors + index);
      PollFD end = *(descriptors + fdCount--);

      removedFD = removeable.fd;
      removeable.fd = end.fd;
      removeable.events = end.events;
      removeable.revents = end.revents;
      memset(&end,0,sizeof(PollFD));
      printDescriptor(descriptors, fdCount);
      // *(descriptors + index) = *(descriptors + --fdCount); //Replace the address at the index with the new address and decrement the freeCount
      // *(descriptors + fdCount + 1) = 0; //Erase the address at the previous end
      debug("Successfully removed FD %d from Index : %d \n", removedFD, index);
      goOnVacation(&fdMutex, FD_SEM);

      verbose("END - Remove FD! --> Success");
}
*/



bool isDuplicateNode(uNodeP start, char* name){
	 
	uNodeP node = start;

  	if(! node){
  		//debug("No starting node!\n");
  		return false;
  	}

  do{
    if(! strcmp(node->user->name, name)) return true;
    node = node->next;
  }while(start && node != start); //While there are more processes

  return false;
}


bool isDuplicateChatroom(char* name){
  verbose("Is Duplicate Chatroom!");
  chatNodeP node = chatrooms;


  if(! node) return false;

  do{
    if(! strcmp(node->room->name, name)){
    	verbose("END Is Duplicate Chatroom! : Returning true");
    	return true;
    }
    node = node->next;
  }while(node && node != chatrooms); //While there are more processes

  verbose("END Is Duplicate Chatroom! : Returning False!");
  return false;
}

void enqueueMessage(echoP msg){
	echoP head = messageQueue;

	pass320(&echoMutex, ECHO_SEM);
	
	//debug("Enqueuing a message now!\n");

	if(! msg){
		error("Cannot add an empty message!\n");
	} 
	else if(head == NULL){ //None have been added
    	messageQueue = head = msg;
    	head-> next = head->prev = msg;
    }
    else if(head->prev == head){ //There's only one
        msg-> next = msg-> prev = head;
        head->next = head->prev = msg;
    }
    else{ //At least 2
	    echoP oldTail = head->prev; //Temporarily store the old tail
	    oldTail-> next = msg;
	    msg-> prev = oldTail; 
	    msg-> next = messageQueue;
	    head-> prev = msg;
	}

	goOnVacation(&echoMutex, ECHO_SEM);

	alarm(ALARM_WAIT_TIME); //Wait 1 second before notifying the thread
	//debug("Done Enqueuing!\n");
}

echoP dequeueMessage(){
	if(! messageQueue) return NULL;

	pass320(&echoMutex, ECHO_SEM);

	echoP returnValue, head;
	returnValue = head = messageQueue;

	if(head->next == head){//only one
		messageQueue = NULL;
	}
	else{ // at least 2
	      echoP nextOne = head->next;
	      head->prev->next = nextOne;
	      nextOne->prev = head->prev;
	      messageQueue = nextOne;
	      head-> next = head-> prev = NULL; //Remove all connections to it
	}
	//debug("Returning head message :%s\n", returnValue->message);

	goOnVacation(&echoMutex, ECHO_SEM);
	return returnValue;
}

/******************** Connection ****************************************/



int server_fetchBindListenSocket(struct addrinfo* list){
	struct addrinfo* node;
	int listenFD;
	for(node = list; node; node = node->ai_next){

		if((listenFD = socket(node->ai_family,node->ai_socktype,node->ai_protocol)) < 0) continue;

		int val = 1;
		if((setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, (const void *)&val, sizeof(int))) < 0){
			error("%s\n", strerror(errno));
		}

		if((bind(listenFD, node->ai_addr, node->ai_addrlen)) == 0){
			break;
		}

		Close(listenFD);
		
	}

	//Getting host info
	void *addr;
	char ipstr[INET_ADDRSTRLEN];
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)node->ai_addr;
	addr = &(ipv4->sin_addr);
	inet_ntop(node->ai_family, addr, ipstr, sizeof(ipstr));


	debug("Connected as host %s \t port: %s\n", ipstr, PORT_NUMBER);

	freeaddrinfo(list);

	if(listen(listenFD, MAX_LISTEN_Q) < 0){
		Close(listenFD);
		node = 0;
	}


	return (node)? listenFD: -1;
}


/******************** END Connection ************************************/

/*********Server Commands **************/


bool fillStringCreateEchoCmdAndEnqueue(char* fromUser, char* string, char* args, uNodeP toUsers){
	char * arguments = fillString(string, args);
	return createEchoCmdAndEnqueue(fromUser, arguments, toUsers);
}

bool createEchoCmdAndEnqueue(char* fromUser, char* arguments, uNodeP toUsers){


	char* buffer = Calloc(1, MSG_BUFFER);
	strncpy(buffer, arguments, MSG_BUFFER_MIN);

	char* buf = buildEchoString(fromUser, buffer);
	createEchoFreeAndEnqueue(ECHO_CMD, buf, toUsers);

	free(buffer);

	return true;
}


bool createEchoAndEnqueue(const char* command, char*msg, uNodeP user){
	echoP echo;

	verbose("Creating Echo and Enqueing!");


	if(! (echo = createEcho(command, msg))){
		error("Problem creating private echo and Enqueuing %s\n", command);
		return false;
	}

	echo -> users = user;
	enqueueMessage(echo);

	verbose("END Creating Private Echo and Enqueuing!");
	return true;
}

bool createEchoFreeAndEnqueue(const char* command, char*msg, uNodeP user){
	bool returnval = createEchoAndEnqueue(command, msg, user);
	free(msg);
	return returnval;
}

bool createPrivateEchoAndEnqueue(const char* command, char* msg, uNodeP user){
	echoP echo;

	verbose("Creating Private Echo!");


	if(! (echo = createPrivateEcho(command, msg))){
		error("Problem creating private echo and Enqueuing %s\n", command);
		return false;
	}
	//debug("Created PRivate echo and about to Enqueue!\n");

	echo -> users = user;
	enqueueMessage(echo);

	verbose("END Creating Private Echo!");
	return true;
}

bool createPrivateEchoFreeAndEnqueue(const char* command, char*msg, uNodeP user){
	bool returnval = createPrivateEchoAndEnqueue(command, msg, user);
	free(msg);
	return returnval;
}

chatDataP CreateChatRoom(userP adm, char *name){
	verbose("Create Chatroom!");
	
	char* chatName = copyString(name);
	chatroomP chatroom = createChatP(adm, chatName);
	chatDataP returnVal = Calloc(1,sizeof(ChatroomData));
	returnVal -> newRoom = chatroom;
	returnVal -> isError = 0;

	if(!chatroom){
		error("There was a problem Creating the chatroom !\n");
		verbose("END Create Chatroom --> Fail");
		free(returnVal);
		returnVal->isError = 1;
	}
	chatroom -> id = ++totalChatrooms;
	chatroom -> numOfUsers = 1;

	//printChatroom(chatroom);
	verbose("END Create Chatroom!");

	return returnVal;
}




chatDataP createPrivateRoom(userP admin, char*name, char* password){
	verbose("Create Private Chatroom!");

	chatDataP rv = CreateChatRoom(admin, name);

	if(rv->isError){
		error("Error, couldn't create chatroom!\n");
		rv-> isError = 1;
		return rv;
	}

	if(! validatePassword(password)){
		error("Password is not valid\n");
		rv-> isError = 2;
		return rv;
	}

	if(! (associatePasswordToChatroom(rv->newRoom, password))){
		error("There was an error associating password to chatoom\n");
		rv-> isError = 3;
		return rv;
	}

	if(! addChatroom(rv->newRoom)){
		error("There was an error adding chatroom to the chatroom list\n");
		rv->isError = 4;
		return rv;
	} 

	verbose("END Created Private Chatroom!");

	return rv;
}

void KickUser(chatroomP room, userP user){
	removeUserNode(room->users, user);
}

bool Msg(userP user, char* message){
	verbose("MSG Start!");

	if(user -> room == waitingRoom) {
		verbose("END MSG : User is in waiting room!");
		return false;
	}

	echoP echo = createEcho(ECHO_CMD, message);
	echo -> users = user->room->users;
	enqueueMessage(echo);

	verbose("END MSG : Success!");
	return true;
}

uNodeP MsgPrivate(userP fromUser, char* toUser){ //TODO : make sure message gets FREE'd

	verbose("MSG Private!");
	if(fromUser -> room == waitingRoom) {
		verbose("END MSG Private : The current user is not in the room!");
		return NULL;
	}

	debug("Sending msg from %s to %s in chatroom %s\n", fromUser->name, toUser, fromUser->room->name);
	bool isFound = false;
	uNodeP head,start;
	head = start = fromUser->room->users;
	do 
	{
		if(! strcmp(start->user->name, toUser)){
			isFound = true;
			break;
		}
		start = start->next;
	}while(start && start!= head);

	if(! isFound){
		verbose("END MSG Private : Username not found!");
		return NULL;
	}

	verbose("END Leaving Chatroom : Success!");
	return start;
}

chatDataP CreateRoom(userP admin,char *name,char *password){
	verbose("Creating Chatroom!");
	if(isDuplicateChatroom(name)){
		verbose("END Creating Chatroom --> Duplicate!");
		return NULL;
	}

	chatDataP rv = (! password)? 
			CreateChatRoom(admin, name) : createPrivateRoom(admin, name, password);

	verbose("END Creating Chatroom!");
	return rv;
}

bool Leave(userP user){
	verbose("Leaving ChatRoom!");

	if(user-> room == waitingRoom){
		verbose("END Leaving Chatroom : Can't leave waiting room!");
		return false;
	} 

	chatroomP room = user->room;
	nodeDataP node;

	if(! room->users){
		verbose("END Leaving Chatroom : No users in the room!");
		return false;
	}

	node = removeUserNode(room->users, user);

	
	if(node-> isError){
		error("There was a problem leaving the room!");
	}
	else{ 

		room->users = node->headOfList;
		room-> numOfUsers--;
		user-> room = waitingRoom;

		if(! node->headOfList){// No more users left?
			closeRoom(room); //No more users, close that bitch

		}
		else{

			if(user == room->admin){
				room->admin = node->headOfList->user; //removeUserNode will return the next available
				fillStringCreateEchoCmdAndEnqueue(SERVER, GENERIC_SERVER_MSG[PROMOTED], room->admin->name, room->users);
			}	
		}


		
		
	}

	free(node);
	
	verbose("END Leaving Chatroom : Sucess!");
	return true;
}

bool closeRoom(chatroomP chatroom){
	verbose("Closing ChatRoom!");
	removeChatroomNode(chatroom);
	debug("Updating chatrooms to %lu\n", (--chatroomCount));
	verbose("END Closing ChatRoom!");
	return FreeChatroom(chatroom);
}


chatNodeP findRoom(int id){


	verbose("Finding ChatRoom!");

	chatNodeP head,start;
	bool isFound = false;

	head = start = chatrooms;

	if(! head){
		verbose("END Finding Chatrooms : There are no chatrooms available");
		return NULL;
	}


	do
	{	if(start->room->id == id){
			isFound = true;
			break;
		}

		start = start->next;
	}while(start && start != head);


	verbose("END finding ChatRoom!");
	return (isFound) ? start : NULL;
}


bool JoinRoom(userP user, int id){
	verbose("Joining Room!");
		
	chatNodeP node = findRoom(id);
	if(node){

		bool added = addUserToChatroom(node, user);

		if(added){
			node -> room -> numOfUsers++;
			verbose("END Joining Room %s! Success!", node->room->name);
		}
		else{
			verbose("END Joining Room %s! Fail!!", node->room->name);
		}
		
		
		return added;
	}
	else{
		verbose("END Joining Room! : Could not find ID");
		return false;
	}

}

bool addUserToChatroom(chatNodeP chatNode, userP user){

	uNodeP newNode = createUserNode(user);
	nodeDataP data = addUserNode(chatNode->room->users, newNode);

	if(data->isError){
		error("There was a problem adding the user to the room!\n");
		free(newNode);
		return false;
	}
	else{
		chatNode->room->users = data -> headOfList;
	}

	user->room = chatNode->room;


	return true;
}


int JoinPrivateRoom(userP user, int id, char *password){
	verbose("Joining Private Room!");
	chatNodeP node = findRoom(id);
	if(!node){
		verbose("END Joining Private Room! --> Could not find the room with ID %d", id);
		return 1;
	}


	passP encryptedPassword = encryptPassword(password, node->room->password->salt);
	debug("Generated password --> \n");
	// printpassP(encryptedPassword);
	if(! comparePassP(node->room->password, encryptedPassword)){
		error("Passwords are not the same, can't join the room!\n");
		return 2;
	}

	bool added = addUserToChatroom(node, user);
	
	if(! added){
		error("There was a problem adding user to chatroom!\n");
		return 3;
	}

	node -> room -> numOfUsers++;

	verbose("Joining Private Room! %s ---> Success!", node->room->name);
	return 0;
}


bool Bye(int fd, userP user){

	verbose("BYE!");

	if(! user){
		error("There is no user!\n");
		return false;
	}

	user->isAuthenticating = false;
	user->isLoggedIn = false;

	if(user->room != waitingRoom && ! Leave(user)){
		error("There was a problem leaving the chatroom for user %s\n", user->name);
		return false;
	}
	
	removeUser(fd);
	

	verbose("END BYE!");
	return true;
}


int kick(userP admin, userP user){ //TODO : Add funny message if admin kicks themselves outs
	verbose("Kicking User!");
	if(admin->room != user->room){
		error("Admin %s is not in the same room as %s\n", admin->name, user->name);
		return 1;
	}
	else if(user->room->admin != admin){
		error("User %s is not the admin of room %s\n", admin->name, user->room->name);
		return 2;
	}

	if(! Leave(user)){
		error("There was a problem Kicking the user %s from chatroom %s\n", user->name, user->room->name);
		return 3;
	}

	verbose("END Kicking User!");
	return 0;
}


char* ListRooms(){

	verbose("Listing Rooms!");
	chatNodeP head,start;
	start = head = chatrooms;
	char* buffer;



	if(! head){
		buffer = Calloc(1, 2 + strlen(CR_LF_2) + strlen(NO_CHATS)); //no_rooms -1_CRLFCRLF\0
		strcat(buffer, NO_CHATS);
		strcat(buffer, " ");
		strcat(buffer, CR_LF_2);
	}
	else{

		int sum = 0;
		int lengthEndAndSpace = 4 + strlen(CR_LF); //NAME_ID_Type_CRLF_, three spaces and one CRLF
		do
		{	sum = sum + lengthEndAndSpace + strlen(start->room->name) + integerLength(start->room->id) + 1; //The 1 is for the public/private flag
			start = start->next;
		}while(start && start != head);

		sum = sum + strlen(CR_LF);
		buffer = Calloc(1, sum); //NAME_ID_type_CRLF_NAME1_ID1_type1_CRLFCRLF\0

		start = head;

		do 
		{	
			strcat(buffer, start->room->name);
			strcat(buffer, " ");

			char *id = itoa(start->room->id);
			strcat(buffer, id);
			free(id);

			strcat(buffer, " ");
			strcat(buffer , ((start->room->password)? "2": "1")); //If there's a password add 1
			strcat(buffer, " ");
			strcat(buffer, CR_LF);
			strcat(buffer, " ");
			start = start->next;
		}while(start && start != head);

		strcat(buffer  + strlen(buffer) - 1, CR_LF);
	}
	
	verbose("END Listing rooms : Returning |%s|\n", buffer);
	return buffer;
}

int integerLength(int a){
	/*int length = 0;
	while((a = a/10) > 0) ++length;
*/
	int length = snprintf(NULL, 0, "%d", a);
	return length;
}

char* itoa(int i){
	int length = integerLength(i);
	
	char* buf = Calloc(1, length + 1);
	snprintf(buf, sizeof(buf), "%d", i);
	//snprintf(buf, length, "%d", i);

	

	verbose("Converted integer %d to string %s", i, buf);
	return buf;
}

char* ListUsers(userP user){
	verbose("List Users!");
	uNodeP head,start;
	start = head = user->room->users;

	if(! head || user -> room == waitingRoom){
		verbose("END Listusers :  there are no users in the room or in the waiting room!");
		return NULL;
	}

	int sum = 0;
	int lengthEndAndSpace = 1 + strlen(CR_LF); //NAME_CRLF, 1 space and one CRLF
	do
	{	sum = sum + lengthEndAndSpace + strlen(start->user->name);
		start = start->next;
	}while(start && start != head);

	sum = sum + strlen(CR_LF);
	char* buffer = Calloc(1, sum + 1); //1 for \0

	start = head;
	do 
	{	
		strcat(buffer, start->user->name);
		strcat(buffer, " ");
		strcat(buffer, CR_LF);
		start = start->next;
	}while(start && start != head);

	strcat(buffer, CR_LF);

	verbose("END List Users : Success!");
	return buffer;

}


userP createUser(int fd, char* name){

	debug("Creating the user %s for FD %d\n", name, fd);
	
	char* userName = copyString(name);
	userP newUser = createUser_helper(fd, userName, waitingRoom);

	debug("Putting the user!\n");
	if(!putUser(name, newUser) || !putUserFD(fd, newUser)){
		debug("User %s already exists!\n", name);
		FreeUser(newUser);
		return NULL;
	}


	
	return newUser;
}


bool addPassword(int fd, char* password){
	userP user;
	debug("Adding password!\n");
	if(! (user = getUserFD(fd))){
		error("Error, User not found!/problem retrieving user\n");
		return false;
	}

	return associatePasswordToUser(user, password);
}

bool associatePasswordToChatroom(chatroomP room, char* password){


	passP passEncrypt;
	unsigned char* salt = generateSalt();
	if(! (passEncrypt = encryptPassword(password, salt))){
	 	error("There was a problem encrypting the password %s\n", password);
	 	FreeChatroom(room);
	 	return false;
	 }
	 room->password = passEncrypt;	

	 

	 return true;
}

bool associatePasswordToUser(userP user, char* password){
	passP encryptedPass;

	debug("Associating Passwords to Users!\n");

	if(! validatePassword(password)){
		error("Password Not Valid!\n");
		return false;
	}

	debug("Password validated!\n");
	
	unsigned char* salt = generateSalt();
	if(! (encryptedPass = encryptPassword(password, salt))){
		error("There was a problem encrypting the password!\n");
		return false;
	}
	user->password = encryptedPass;

	return true;
}

userP loginStep1(int fd, char* name){
	userP user;

	if(! (user = getUser(name))){
		error("User Not Found!\n");
		return NULL;
	}

	if(!(putUserFD(fd, user))){
		error("There was a problem assigning FD %d to user %s\n", fd, name);
		return NULL;
	}

	removeUser(fd);

	user->fd = fd; //Reset the user FD
	return user;
}

bool loginComplete(int fd, char* password){
	userP user; 

	if(! (user = getUserFD(fd))){
		error("User Not Found!\n");
		return false;
	}

	passP encryptedPassword = encryptPassword(password, user->password->salt);
	if(! comparePassP(user->password, encryptedPassword)){
		error("Passwords are not the same, can't join the room!\n");
		return false;
	}

	return true;
}

/**********END Server Commands**************/


/***************FREE Methods****************/

bool FreeChatData(chatDataP data){
	verbose("Free Chat Data");
	if(data->isError && data->newRoom){
		free(data->newRoom);
	}

	free(data);

	verbose("END Free Chat Data");
	return true;
}


bool FreeChatroom(chatroomP chatroom){

	verbose("FreeChatroom!");
	uNodeP start, head, temp;
	start = head = chatroom->users;
	if(! start) return false;

	do
	{
		temp = start->next;
		debug("Freeing UserNode! %s\n", start->user->name);
		free(start);
		start = temp;
	}while(start && start != head);

	if(chatroom->password){
		debug("Freeing password!");
		free(chatroom->password);
	}
	debug("Freeing chatroom!");
	free(chatroom);

	verbose("END FreeChatroom! --> Success");
	return true;
}

bool FreeEcho(echoP echo){

	uNodeP start, head;
	start = head =echo->users;
	if(! start) return false;

	debug("Freeing Echo!\n");
	do
	{
		if(start->isFreeable ){
			if(start->user){

				nodeDataP node = removeUserNode(start, start->user);

				if(node->isError){
					error("There was a problem removing the user!\n");
				}
				else if(start->user->isFreeable){
					FreeUser(start->user);
				}

				start = node->headOfList;
			}
			
			
		}
		else{
			start = start->next;
		}
	}while(start && start != head);

	free(echo->message);
	free(echo);

	return true;
}

bool FreeUser(userP user){

	//debug("Started Free User!\n");
	if(user->password){
		//debug("About the free the password!\n");
		free(user->password);
	}
	if(user->session){
		free(user->session);
	}
	free(user);
	debug("Free'd the User!\n");
	return true;
}


bool FreePollP(pollP poll){
	if(! poll) return false;

	free(poll);
	return true;
}

bool FreeConnection(connP conn){
	if(! conn) return false;

	free(conn->connAddr);
	free(conn);
	return true;
}

/************END FREE **********************/


/*************** Password validation/Encryption **************/

bool validatePassword(char * password){
	verbose("Validate Password!");
	bool sym = false, up = false, num = false;
	int length = strlen(password);

	if(strlen(password) < MIN_PASS_LENGTH){
		verbose("END Validate Password! : Password less than min length");
		return false;
	}

	char c; int i;
	for(c = '\0', i = 0; i < length; i++){
		c = *(password + i);
		if(c > '0' && c < '9') num = true;
		else if(c > 'A' && c < 'Z') up = true;
		else if((c >= ' ' && c < '0') || (c > '9' && c < 'A') 
					|| (c > 'Z' && c < 'a') || (c > 'z' && c < 127)) sym = true;
	}

	verbose("END Validate Password: Success!");
	return num && up && sym; // Only true if all 3 constraints are met
}

passP encryptPassword(char* password, unsigned char* salt){
	debug("Encrypt Password |%s| with salt -->|", password);
	//printUnsignChar(salt, MAX_SALT);

	char * pwd = trim(password);
	int length = strlen(pwd) + MAX_SALT + 1;
	char passSalt[length];
	memset(&passSalt, 0, length);
	strcat(passSalt, pwd);
	memcpy(passSalt + strlen(pwd), salt, MAX_SALT);

	debug("Callocing space!\n");

	unsigned char * mDigest = Calloc(1, SHA_DIGEST_LENGTH * sizeof(unsigned char));


	//debug("Creating the Digest!\n");

	if(! (SHA1((unsigned char *)passSalt, length, mDigest))){
		error("Failed to generate SHA1 HASH");
		free(mDigest);
		return NULL;
	}

	passP mHash = createPassP(mDigest, SHA_DIGEST_LENGTH, salt);

	debug("Printing password --> \n");
	//printpassP(mHash);

	verbose("END Encrypt Password! : success");
	return mHash;
}

unsigned char* generateSalt(){
	unsigned char* buf = Calloc(1, MAX_SALT);
	int ret;

	for(int i = MAX_SALT; i > 0; i--){

		if((ret = RAND_bytes(buf, MAX_SALT)) == 0){ //Failure

			continue;
		}

		break;
	}

	//debug("Generated Salt! ");
	//Write(1, buf, MAX_SALT);
	//debug("\n");

	//debug("Generating the Salt!!\n");
	return buf;
}


/*************** END Password validation/Encryption **************/



pthread_t Create_Thread(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg){
	
	int err = errno;
	errno = 0;

	pthread_create(thread, attr, start_routine,arg);
	if(errno){
		error("There was an error creating the Thread! : %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	errno = err;
	return *thread;
}

int Detach_Thread(pthread_t thread){
	int returnVal;


	int err = errno;
	errno = 0;

	returnVal = pthread_detach(thread);

	if(errno){
		error("There was an error Detaching the Thread! : %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	errno = err;
	return returnVal;
}


void pass320(sem_t * jwong, char* name){
	//verbose("Pass 320!");
	if(sem_wait(jwong)){
		error("There was an error passing 320!\n");
	}
	else{
		verbose("RUN 320 RUN! %s", name);
	}
	
}

void goOnVacation(sem_t * jwong, char* name){
	//verbose("Blocked!");

	if(sem_post(jwong)){
		error("There was an error going on vacation!!\n");
	}
	else{
		verbose("GO ON VACATION! %s", name);
	}
}

bool start320(sem_t * mutex, int defaultValue){
	//sem_t* mutex = Calloc(1, sizeof(sem_t));

	if(sem_init(mutex, 0, defaultValue)){
		error("There was an error going on vacation!!\n");
		free(mutex);
		return false;
	}

	return true;
}


void get320ProgressReport(){

	verbose("320 Progress Report!");

	debug("FD Midterm : --> %d\n", getMidtermGrade(&fdMutex));
	debug("User Midterm : --> %d\n", getMidtermGrade(&userMutex));
	debug("ECHO Midterm : --> %d\n", getMidtermGrade(&echoMutex));

	verbose("END - 320 Progress Report!");
}


/***************** Polling **********************************/


	int CreateEPoll(int flags){
		int fd;
		if((fd = epoll_create1(flags)) < 0){
			error("There was a problem creating Epoll FD, {%d --> %s}\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		return fd;
	}


	int unblockFD(int fd){

		int flags, rv;
		flags = fcntl (fd, F_GETFL, 0); //Get the Flags
	  	
	  	if (flags < 0)
	    {
	      error("Error getting flags!\n");
	      exit(EXIT_FAILURE);
	    }

 		flags |= O_NONBLOCK;
  		rv = fcntl (fd, F_SETFL, flags);
	  
	  	if (rv < 0)
	    {
	      error("Error setting FD to nonblocking");
	      exit(EXIT_FAILURE);
	    }

		return 0;
	}


	int addEPollFD(int fd){

		if(fdCount > MAX_CONN){
			return -1;
		}

		unblockFD(fd);

		pass320(&fdMutex, FD_SEM);

		ePollP poll = &*(descriptors + (fdCount++));
		poll-> data.fd = fd;
		poll->events = EPOLLIN | EPOLLET;


		int rv;
		if((rv = epoll_ctl (eFD, EPOLL_CTL_ADD, fd, poll)) < 0){
			error("hmm\n");
		}

		goOnVacation(&fdMutex, FD_SEM);

		return rv;
	}

	void removeEPollFD(int index)
	{
		verbose("Remove FD! for Index %d", index);

		int removedFD;

		pass320(&fdMutex, FD_SEM);

		// printDescriptor(descriptors, fdCount);

	    if(index < 0) error("No FD exist!\n");

	    ePollEvent removeable = *(descriptors + index);
	    ePollEvent end = *(descriptors + fdCount--);

	    int rv;
		if((rv = epoll_ctl (eFD, EPOLL_CTL_DEL, removeable.data.fd, NULL)) < 0){
			error("Hmm\n");
		}

	    removedFD = removeable.data.fd;
	    removeable.data.fd = end.data.fd;
	    removeable.events = end.events;
	    memset(&end,0,sizeof(ePollEvent));
	      
	    //printDescriptor(descriptors, fdCount);
	    //*(descriptors + index) = *(descriptors + --fdCount); //Replace the address at the index with the new address and decrement the freeCount
	    //*(descriptors + fdCount + 1) = 0; //Erase the address at the previous end
	    debug("Successfully removed FD %d from Index : %d \n", removedFD, index);

	    goOnVacation(&fdMutex, FD_SEM);

	    verbose("END - Remove FD! --> Success");
}

	
	int EPollWait(ePollP events, int maxEvents){
		verbose("EPOLL Waiting!");
		int total;

		total = epoll_wait(eFD, events, maxEvents, -1);

		verbose("END EPOLL Waiting!");
		return total;
	}






/************************************************************/








