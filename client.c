#include "aloha.h"

bool createNewUser = false;
bool isAuthenticated = false;// should stay false until it gets the high name
bool isInRoom = false;
int client_fd;
char *username;
char *sessionId;
int numOfStrs = 0;
bool isSessionEnabled = false;

struct timeval tv;

#ifdef DJTEST
    int ctr  = 0;
#endif


int main(int argc, char  *argv[]){

// #ifdef GUIACTIVE
//     bool isGuiActive = true;
//geendif

// #ifndef GUIACTIVE
//     bool isGuiActive = false;
// #endif


    int opt;
    char *server_IP;
    char *server_port;
    #ifndef DJTEST
        struct addrinfo *listp;
    #endif
    // int status;
        while((opt = getopt(argc, argv, "hcs")) != -1) 
        {
            switch(opt) 
            {
                case 'h':
                /* The help menu was selected */
                CLIENT_CMD_HELP();
                /*TODO: put function to display help*/
                exit(EXIT_OK);
                break;
                case 'c':
                /* a new user will be created */
                createNewUser = true;
                /*TODO: put function to display help*/
                break;
                case 's':
                isSessionEnabled = true;
                break;
            }

        }
    // if(isGuiActive){
    //     switch(forkProcess())
    //     {
    //         case -1:
    //             error("uh oh\n");
    //             break;
    //         case 0:
    //             app = gtk_application_new ("chatroom.ui", G_APPLICATION_FLAGS_NONE);
    //             g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
    //             //TODO may have to fork here
    //             status = g_application_run (G_APPLICATION (app), argc, argv);
    //             g_object_unref (app);
    //         default:
    //             debug("Main thread keeps going");
    //     }

    // }


    if(optind < argc) 
    {
        username = argv[optind++];
        server_IP = argv[optind++];
        server_port = argv[optind++];
    } 
    else {
        
        if((argc - optind) <= 0) {
            std_error("Missing SERVER_IP and SERVER_PORT.\n");
        }
         else if((argc - optind) == 1) {
            std_error("Missing SERVER_IP or SERVER_PORT.\n");
        } 
        else {
            std_error("Too many arguments provided.\n");
        }

        exit(EXIT_FAIL);
    }


    #ifdef DJTEST
    char *test;

    char love[] = "/listrooms";

    test = Calloc(1,strlen(love) + 1);
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything
    strcpy(test,love);
    client_parseBufferUser(test);//when i write the actual code i need to free everything

    free(test);

    verbose("%d",ctr);
    #endif

    #ifndef DJTEST
    listp = Getaddrinfo(server_IP,server_port,CLIENT_AI_FLAGS);
    debug("Got listp now getting clientfd\n");
    client_fd = client_connectSocket(listp);
    debug("client_fd is: %d\n",client_fd);

    client_initHandShake(client_fd);

    client_CreateIRCConnection(client_fd);
    #endif

    //now handle parsing for luck and life
    return EXIT_OK;
}


int client_connectSocket(struct addrinfo *listp) {
    struct addrinfo *p;
    int clientfd;
    for (p = listp; p ; p = p->ai_next)
    {
        if ( (clientfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) < 0 )
            continue; /* Socket failed, try the next */    
        if (Connect(clientfd, p->ai_addr, p->ai_addrlen) == 0)
            {
                
                setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
                debug("We founds it\n");
                break; /* Success */
            }
        verbose("%d",clientfd);
        close(clientfd); /* Connect failed, try another */
   }
    freeaddrinfo(listp);
    return (p) ? clientfd : -1;
}


void client_CreateIRCConnection(int clientfd) {

    fd_set read_set, ready_set;
    char buffer[MAX_LINE]; 
    char *message;

    FD_ZERO(&read_set);
    FD_SET(STDIN_FILENO, &read_set);
    FD_SET(clientfd, &read_set);
    memset(buffer,0, MAX_LINE);

    SignalFunc(SIGPIPE, signal_interrupt);
    SignalFunc(SIGTSTP, signal_interrupt);


    tv.tv_sec = 6;  /* 30 Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors


    while(true && !stop_signal)
    {

        SignalFunc(SIGPIPE, signal_interrupt);
        SignalFunc(SIGTSTP, signal_interrupt);

        // verbose(" %d ",stop_signal);
        ready_set = read_set;
        //TODO add wrapper for  for timmer
        Select(clientfd+1,&ready_set);
        // verbose("Did you hang up");
        if(FD_ISSET(STDIN_FILENO, &ready_set))// read from stdin if there is a signal and the user is true
        {
            // debug("Yo write me something special \n");
            // output("%s >",username);
            Read(STDIN_FILENO,buffer, MAX_LINE);
        
            *(buffer + strlen(buffer) - 1) = '\0';//removes new line from person
            *(buffer + MSG_BUFFER) = '\0';//makes sure the message is only 1001
            verbose("String Length: %lu",strlen(buffer));
            if(isAuthenticated)
                {
                    message = client_parseBufferUser(buffer);
                    debug("message being sent: %s\n",message);
                    if(message != NULL)
                    {
                        Send(clientfd,message);
                        debug("Freeing sent meessage\n");
                        free(message);
                    }

                }
        }
        if(FD_ISSET(clientfd, &ready_set))
        {
            //Use Recv when message
            if(recv(clientfd,buffer, MAX_LINE,0) > 0)
              {
                // need to add logic to loop
                verbose("receive string %s of length: %lu", buffer,strlen(buffer));
                client_parseBufferServer(buffer);
              } 
              else 
                // if(errno == EPIPE || errno == EAGAIN  || errno == EWOULDBLOCK)
                {
                    output("Did you just hang up on me\n");
                    // verbose("errno is %d",errno);
                    free(sessionId);
                    stop_signal = 1;

                } 
        }
    memset(buffer,0,MAX_LINE);
    }

    Close(clientfd);

}


void client_initHandShake(int clientfd){
    if(clientfd < 0 )
        return;

    char *message = generateSingleMessage(INTRO_CLIENT);
    debug("message being sent over %s\n",message);
    Send(clientfd, message);
    debug("freeing handshake message");
    
    if(message){
        free(message);
    }

}

char *generateSingleMessage(const char *command){
    return generateMessage(command,"");
}
char *generateMessage(const char *command, char *buffer){

    verbose("Generating Message");


    int length = strlen(command) + strlen(CR_LF) + 1; 
    if(isSessionEnabled && sessionId)
    {
        length = length + strlen(sessionId) + 1;
        // verbose("found lenth of String");
    }
    if(buffer)
    {
        length = length + strlen(buffer) + 1;
    }

    char *message = Calloc(1,length + 1); //command_Buffer_CRLF\0
    strcat(message,command);
    strcat(message, SPACE);


    if(buffer && (strcmp(buffer,"") != 0))
    {   
        strcat(message,buffer);
        strcat(message,SPACE);
    }
    if(isSessionEnabled && sessionId)
    {
        // verbose("concating the sessionId");
        strcat(message,sessionId);
        strcat(message,SPACE);
    }

    //strcat(message,SPACE);
    strcat(message,CR_LF);
    debug("\nmessage: %s\n",message);
    verbose("Message generated Success");
    return message;

}

void client_parseBufferServer(char *response){
    char *arguments;
    char *command;
    char *message;
    char buffer[MSG_BUFFER];
    char *strDelim;
    const char *delim = " ";
    char *addrNextWord;

    strDelim = client_isCommandList(response) ? CR_LF_2 : CR_LF ;
    // verbose("About to parse the response %s",response);

    if(strcmp(response,"") == 0){
        debug("Empty Response!\n");
        return; //If empty response
    }

    while((response=strtok2_O(response,strDelim))!= NULL && strcmp(response,"") != 0)// \r\n
    {
        verbose("Parsing Response %s", response);

        #ifdef DJTEST
            ctr++;
        #endif

        addrNextWord = response + strlen(response) + strlen(strDelim);// address of the next word
        response = trim(response);
        
        debug("The response is %s\n",response);
        if(!client_isAckValidFormat(response))
        {
            error("this ACK is bad it might as well be an NAK\n");
        }



        command = strtok(response,delim);
        arguments = (response + strlen(command)+1);



        // I can check here if the arguments are greater then 1000
        if(strlen(arguments) > MSG_BUFFER)
            *(arguments + MSG_BUFFER) = '\0';



        // debug("About to start comparing commands with command %s\n",command);
        if(!isAuthenticated && strcmp(command,INTRO_SERVER) == 0)
        {
            debug("Receieved responsed from Server !AHOLA\n");
            if(createNewUser)//Send IAMNEW
            {
                message = generateMessage(CREATE_USER, username);
            }
            else// IAM
            {
                message = generateMessage(LOGIN, username);
            }

            if(message){
                Send(client_fd,message);
                debug("Sent message %s\n",message);

                free(message);
            }
            
        }
        else if(! isAuthenticated && strcmp(command,LOGIN_COMPLETE_ACK) == 0)
        {

            debug("User is officially logged in\n");

            verbose("About to grab session");
            if(isSessionEnabled){
                char *sesh;
                verbose("I should be getting the SessionId");
                sesh = findSession(arguments);
                sessionId = copyString(sesh);
                verbose("Session Id is %s" ,sessionId);
            }
            isAuthenticated = true;

        }
        else if(!isAuthenticated && createNewUser && strcmp(command,CREATE_USER_ACK) == 0)//HINEW
        {
                output("Please Enter a New Password : ");
                ReadBuffer(STDIN_FILENO,buffer);

                *(buffer + strlen(buffer) - 1) = '\0';// removes the new line
                message = generateMessage(CREATE_PASS,buffer);

                Send(client_fd,message);
                debug("Freeing HINEW meessage\n");
                free(message);


                debug("Received HINEW from the server\n");

        }
        else if(!isAuthenticated && strcmp(command,LOGIN_AUTH_ACK) == 0)//AUTH
        {
                output("Please Enter your Password\n");
                //read from the command line
                ReadBuffer(STDIN_FILENO,buffer);

                *(buffer + strlen(buffer) - 1) = '\0';// removes the new line

                message = generateMessage(PASSWORD,buffer);
                Send(client_fd,message);

                debug("Freeing password meessage\n");
                free(message);


                debug("Received AUTH\n");
        }


        /****** Should be Successfully Logged in at this point ******/


        // if(! isAuthenticated){
        //     output("There was a Server Error, Exiting...\n");
        //     ByeCmd();
        // }



        if(strcmp(command,ECHO_CMD) == 0)
        {
            debug("Echo ACK received\n");
            // should print in the format name of user > MSG
            verbose("Echoing message");
            echoCmd(arguments);
            verbose("Echoing message Success");
        }
        else if(strcmp(command,TELL_CLIENT_PREFIX) == 0)
        {
            debug("EchoP ACK received\n");

            verbose("EchoPing message");
            echoPCmd(arguments);
            verbose("EchoPing message Seccess");

        }
        else if(strcmp(command,JOIN_ACK) == 0)
        {
            char *id = strtok(arguments,SPACE);
            debug("Join ACK received\n");
            debug("The user joined the room %s\n",id);
        }
        else if(strcmp(command,CREATE_ACK) == 0)
        {
            char *name = strtok(arguments,SPACE);
            debug("create room ACK received\n");
            debug("The room %s was created \n",name);

        }
        else if(strcmp(command,CLIENT_KICK_MSG) == 0)
        {
            verbose("About to Kick someone out");
            kickCmd();
            verbose("This nigga done kicked out");

        }
        else if(strcmp(command,LISTROOM_ACK) == 0)
        {
            verbose("listing rooms");
            debug("listroom ACK received\n");
            listRoomCmd(arguments);
            verbose("listrooms Success");
        }
        else if(strcmp(command,LIST_USER_ACK) == 0)
        {
            verbose("listusers");
            debug("list users ACK received\n");
            listUsersCmd(arguments);
            verbose("listusers Success");
        }
        else if(strcmp(command,CLOSE_CONN) == 0)
        {
            debug("Bye ACK received\n");
                ByeCmd();
        }
        else if(strcmp(command,JOIN_PRIVATE_ACK) == 0)
        {       
            debug("JoinP ACK received\n");
            debug("Joined a Private room\n");
        }
        else if(strcmp(command,KICK_ACK) == 0)
        {
            // char *user = strtok(arguments,SPACE);
            debug("kick ACK received\n");
            // kickCmd(arguments);
        }
        else if(strcmp(command,TELL_ACK) == 0)
        {
             debug("Tell ACK received\n");
        }
        else if(strcmp(command,CREATE_PRIVATE_ACK) == 0)
        {
            char *name = strtok(arguments,SPACE);
            debug("create ACK received\n");
            debug("The private room %s was created\n",name);
        }
        else if(strcmp(command,LEAVE_ACK) == 0)
        {
            debug("create ACK received\n");
            debug("Left the room successfully\n");
        }
        else if(strcmp(command,ERROR) == 0)
        {
            // debug("error is %s",arguments);
                printError(arguments);

            debug("error ACK received\n");
        }
        else
        {
            debug("Invalid command received\n");
        }

        debug("Finished comparing and found %s\n",command);
        response = NULL;
        strDelim = client_isCommandList(addrNextWord) ? CR_LF_2 : CR_LF ;

        verbose("END Finished Parsing Response!\n");
    }

}

bool client_isAckValidFormat(char *response){
    char protocol[strlen(response) + 1];
    // char *needle = CR_LF;
    char *delim = " ";
    char *token;
    strcpy(protocol,response);

    token = strtok(protocol,delim);
    //checks if the length of the protcol > 0 if the ack contains \r\n
    if(strlen(token) == 0 )//||  strstr(response,needle) == NULL )
    {   
        return false;
    }
    return true;
}

char *client_parseBufferUser(char *input){
    #ifdef DJTEST
        ctr++;
    #endif

    char *cursor = input;
    char *token;
    char *message;


    const char* delim = " ";
    char *needle = "/";
    input = trim(input);
    debug("The input from the User is %s\n",input);


    if((token = strstr(cursor,needle)) == NULL) //Sending a message
    {
        //if it gets here we don't need to validate the input so we don't care
        debug("The message is a command\n");
        message = generateMessage(SEND_MSG,input);
    }
    else //Sending a Command
    {

        int protocol;
        char *cmd_arguments;

        char copyString[strlen(input)+1];
        memset(copyString,0,strlen(input)+1);
        strcpy(copyString,input);


        token = strtok(cursor, delim);
        cmd_arguments = (cursor + strlen(token) + 1);
        protocol = getProtocolFromString(token);

        debug("command function is initialized\n");
        if(protocol == HELP || protocol == BYE || protocol == MSG)
        {
            return NULL;
        }

        //TODO just pass the arguments down and validate them
        
        if( isCommandValid(protocol,cmd_arguments) )
        {
            const char * protocolStr = getProtocol(protocol);
            message = generateMessage(protocolStr,cmd_arguments);
        }
        else 
        {
            output("command: had invalid parameters. Try again\n");
            message = NULL;
        }

    }


    /****************** Finished Parsing **********************/
    // debug("My error is unfixable\n");

    //rtsil ROOM1 2 2\R\N ROOM2 2 1 \R\N\R\N
    //ECHO server Hey \r\n rtsil ROOM1 2 2\R\N ROOM2 2 1 \R\N\R\N
    return message;
}


bool client_isCommandList(char *response) {

    char* trimResponse = trim(response);
    char* listrooms = strstr(trimResponse,LISTROOM_ACK);
    char* listUsers = strstr(trimResponse, LIST_USER_ACK);

   return (listrooms == trimResponse || listUsers == trimResponse);
}


bool isCommandValid(int protocol, char * cmd_arguments)
{
    bool isValid = false;
    char *arguments;
    char *arg2 = NULL;


    char* space1, 
    *restOfArgs = NULL;

    debug("Validating arguments\n");
    switch(protocol)
    {
        //0 arguments
        case LEAVE:
        case LISTU:
        case LISTR:
        case BYE:
        case _QUIT:
            cmd_arguments = "";
            isValid = true;
            break;



        //1 arguemnt
        case IAM:
        case IAMNEW:
        case PASS:
        case NEWPASS:
        case KICK:
        case JOIN:
        case CREATER:
            arguments =  strtok(cmd_arguments,SPACE);
            if(!arguments)
                isValid = false;
            else
                isValid = true;
            cmd_arguments = arguments;
            break;


        //2 arguments
        case CREATEP:
        case JOINP:


            space1 = strstr(cmd_arguments, SPACE);
            if(space1){
                restOfArgs = cmd_arguments + strlen(space1) + 1; //Puts me past the first space
                char* space2 = strstr(restOfArgs, SPACE);
                if(space2) *(space2) = '\0'; //Ignore everything after the space
            }
            
            arguments = cmd_arguments;
            arg2 = restOfArgs;
            //strtok(cmd_arguments,SPACE);
            //arg2 = strtok((arg2),SPACE);

            if( (arguments && !arg2) || (!arguments && arg2)  || (!arguments && !arg2) )
                 isValid = false;
            else isValid = true;
            break;


        case TELL:

            space1 = strstr(cmd_arguments, SPACE);
            restOfArgs = cmd_arguments + strlen(space1) + 1; //Puts me past the first space

            arguments = cmd_arguments;
            arg2 = restOfArgs;

            if( (arguments && !arg2) || (!arguments && arg2)  || (!arguments && !arg2) )
            {
                isValid = false;
            }
            else isValid = true;
            break;


        default://this is for message or wrong things
            debug("A msg command\n");
            //should remain as false
            isValid = true;
    }


    return isValid;
}

int getProtocolFromString(char *inputBuf) {
    // {ALOHA, IAM, PASS, NEWPASS,HINEW
            if(strcmp(inputBuf,QUIT) == 0)
            {   
                return _QUIT;
            }
            else if(strcmp(inputBuf,HELP_VERB) == 0)
            { 
                CLIENT_CMD_HELP();
                return HELP;
            }
            else if(strcmp(inputBuf,CREATER_CLIENT) == 0)
            { 
                return CREATER;
            }
            else if(strcmp(inputBuf,CREATE_PRIVATE_CLIENT) == 0)
            {  
                return CREATEP;
            }
            else if(strcmp(inputBuf,LISTROOM_CLIENT) == 0)
            {
                return LISTR;
            }
            else if(strcmp(inputBuf,JOIN_CLIENT) == 0)//
            {
                return JOIN;
            }
            else if(strcmp(inputBuf,JOIN_PRIVATE_CLIENT) == 0)//
            {
                return JOINP;
            }
            
            else if(strcmp(inputBuf,LEAVE_CLIENT) == 0)
            {
                return LEAVE;
            }
            else if(strcmp(inputBuf,KICK_CLIENT) == 0)
            {
                return KICK;
            }
            else if(strcmp(inputBuf,TELL_CLIENT) == 0)// max length should be 1000 bytes
            {
                return TELL;
            }
            else if(strcmp(inputBuf,CLOSE_CONN) == 0)
            {
                return BYE;
            }
            else if(strcmp(inputBuf,LIST_USERS_CLIENT) == 0)
            {
                return LISTU;
            }
            //TODO add help
            return MSG;
}
char *getProtocol(int protocol)
{
    switch(protocol)
    {
        case LEAVE:
            return LEAVE_VERB;
        case LISTU:
            return LIST_USERS_VERB;
        case LISTR:
            return LISTROOM_VERB;
        case IAM:
            return LOGIN;
        case IAMNEW:
            return CREATE_USER;
        case PASS:
            return PASSWORD;
        case NEWPASS:
            return CREATE_PASS;
        case KICK:
            return KICK_VERB;
        case JOIN:
            return JOIN_VERB;
        case CREATER:
            return CREATER_VERB;
        case TELL:
            return TELL_VERB;
        case HELP:
            return HELP_VERB;
        case CREATEP:
            return CREATER_PRIVATE_VERB;
        case JOINP:
            return JOIN_PRIVATE_VERB;
        case _QUIT:
            return CLOSE_CONN;
        default:
            return SEND_MSG;
    }
}
/*********************CLIENT RESPONSE FUNCTIONS***********************/

void echoPCmd(char *message)
{
    char *user;
    char *msg;
    if((user = strtok(message,SPACE)) == NULL)
    {
        std_error("There wasn't a user in the return status\n");
    }

    message = (message + strlen(user)+ 1);
    verbose("Building Private message");
    msg = Build_Private_Message(message);

    output("%s > %s\n",user,msg);
    fflush(stdout);
    verbose("freeing Private Message");
    free(msg);

}


void echoCmd(char *message)
{
    char *user;
    if((user = strtok(message,SPACE)) == NULL)
    {
        std_error("There wasn't a user in the return status\n");
    }

    message = (message + strlen(user)+ 1);

    output("%s > %s\n",user,message);
    fflush(stdout);

}
void listRoomCmd(char *response) {
    char *msg;
    bool isPrivate;
    char **cursor;

    char **rooms = client_parseRooms(response);
    cursor = rooms;

    for(int i = 0; i < numOfStrs; i++)
    //while( numOfStrs != (cursor - rooms))
    {
        // verbose("%s\n"response);
        // orgPtr = trim(*cursor);
        msg = ( isPrivate=isPrivateRoom(*cursor) ) ? Build_Private_Message(*cursor) : *cursor;

        output("%s\n",msg);
        if(isPrivate)
        {
            debug("Freeing private message from listrooms\n");
            free(msg);
            isPrivate = false;
        }
        cursor++;
    }


    //roomCtr = cursor - rooms;// number of rooms to free
    int i;
    debug("free individual rooms\n");
    for(i = 0;i < numOfStrs; i++)
    {
        
        free( *(rooms +  i) );
    }

    debug("Freeing main rooms list string\n");
    free(rooms);
}

bool isPrivateRoom(char *response){
    char *room = Calloc(1,strlen(response) + 1);
    char *roomNumber;
    char *orgPtr;

    strcpy(room,response);
    orgPtr = room;
    room = trim(room);

    if( (roomNumber=strtok2_O(room,SPACE)) == NULL )//User
    {
        return false;
    }
    if( (roomNumber=strtok2_O(NULL,SPACE)) == NULL )//id
    {
        return false;
    }
    if(( roomNumber = strtok2_O(NULL,SPACE) ) == NULL) // roomNumber
    {
        return false;
    }
    debug("Freeing string for checking if a rooms is private\n");
    free(orgPtr);
    return ( atoi(roomNumber) == 2 );
}


char ** client_parseRooms(char *response){

    char* copyResponse = copyString(response);

    char ** rooms;
    char * cursor;
    char ** roomCursor;
    numOfStrs = 0;

    cursor = copyResponse;

    while( (cursor = strstr(cursor,CR_LF)) != NULL)//Count the Number of Rooms
    {
            numOfStrs++;
            cursor+= strlen(CR_LF);
    }


    rooms = Calloc(1, ++numOfStrs * sizeof(char *));

    roomCursor = rooms;
    cursor = copyResponse;

    while( ( cursor = strtok2_O(cursor,CR_LF) ) != NULL )
    {
            char *currentRoom = Calloc(1, strlen(cursor) + 1);
            strcpy(currentRoom,cursor);

            *roomCursor = currentRoom;
            roomCursor++;
            cursor = NULL;
    }

    free(copyResponse);

    return rooms;

}
void listUsersCmd(char *response) {
    // char *users;
    //     users = strtok2_O(response,CR_LF_2);
    //     if(  users ==  NULL)
    //     {
    //         std_error("Um This is awkward I can't do this!\n");
    //     }
    output("%s\n",response);
}
void ByeCmd(){
    Close(client_fd);

    if(isSessionEnabled){
        if(sessionId){
            free(sessionId);
        }
        else{
            debug("Session ID was NULL?\n");
        }
    }
    
    exit(EXIT_OK);
}

void kickCmd(){

    char *msg = Build_Info_Message(KICK_MSG);
    debug("kbye ACK received\n");
    output("%s\n",msg);
    fflush(stdout);
    debug("Freeing kicked meessage\n");
    free(msg);
}

void printError(char *error){

    char *printingMessage;

    int len = strlen(ERROR_LINE) + strlen(error) + 2;
    char message[len];
    memset(message,0,len);

    strcat(message,ERROR_LINE);
    strcat(message,SPACE);
    strcat(message,error);

    // debug("You made an Error friend %s\n",printingMessage);
    printingMessage = Build_Error_Message(message);

    output("%s\n",printingMessage);
    debug("Freeing error meessage\n");
    free(printingMessage);

}
/*********************************************************************/






