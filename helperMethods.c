#include "aloha.h"

#ifdef DVERBOSEFLAG
    VERBOSE_LEVEL DEBUG = DEV;
#endif

#ifdef DEBUGFLAG
    VERBOSE_LEVEL DEBUG = VERBOSE;
#else 
    VERBOSE_LEVEL DEBUG = NONE;
#endif

bool isDBInitialized = false;
bool DEBUG_OVERRIDE = false;
sqlite3* userDatabase; //The database!

typedef const enum {CREATE_USRTABLE, CREATE_PASSTABLE, INSERT_USER, INSERT_PASS,
                   SELECT_ALL_USER, SELECT_USER, DELETE_USER, DELETE_PASS,
                    UPDATE_ADDRESS, SELECT_PASS} SQL_STMT;

const char* SQL_STMTS[] = {"CREATE Table User(addr UNSIGNED BIG INT PRIMARY KEY ASC, name VARCHAR(256),"                        \
                            "password UNSIGNED BIG INT,FOREIGN KEY(password) REFERENCES Password(addr));",                                                          
                          "CREATE Table Password(addr UNSIGNED BIG INT PRIMARY KEY ASC,length INTEGER, buffer BLOB, salt BLOB);",                                                          \
                          "INSERT into Usr(addr, name, password) VALUES(?,?,?);",
                          "INSERT into Pass(addr, length, buffer, salt) VALUES(?,?,?,?);",
                          "Select * from User;",
                          "Select * from User WHERE addr = ?;",
                          "DELETE FROM User WHERE addr = ?;",
                          "DELETE FROM Password WHERE addr = ?;",
                          "UPDATE %s SET addr = ? WHERE addr = ?;",
                          "SELECT addr, length, buffer, salt from Password WHERE addr = ?"    
              };

struct addrinfo * Getaddrinfo(char *host, char *port, int flags)
{
    struct addrinfo hints, *listp;
    memset(&hints,0,sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = flags; 
    getaddrinfo(host, port,&hints,&listp);

    return listp;
}


void printpassP(passP enc){
	unsigned char* buf = enc->buffer;

	debug("SHA Digest Length : %d\n", SHA_DIGEST_LENGTH);

  printUnsignChar(buf, enc->length);
}

void printUnsignChar(unsigned char* buf, size_t length){
    for(size_t i = 0; i < length; i++){
      output("%x", *(buf + i));
    }
    output("\n");
}


bool comparePassP(passP enc1, passP enc2){

  verbose("Compare Pass!");

	if(enc1->length != enc2->length){
    verbose("END Compare Pass --> Fail!");
    return false;
  }

	bool misMatch = false;
	unsigned char* buf1 = enc1->buffer;
	unsigned char* buf2 = enc2->buffer;

    debug("Pass 1 : \n");
    //printpassP(enc1);

    debug("Pass 2 : \n");
    //printpassP(enc2);

	//for(size_t i = 0; i < enc1->length; i++){
		if(! memcmp(buf1, buf2, enc1->length)){
			misMatch = true;
    }
	//		break;
		//}
	//}
	

  verbose("Compare Pass! Returning --> %d", misMatch);

	return misMatch;
}


/**
*	fill_error_str returns a Malloc'd string, after use this string should be free'd
*/
char* fill_error_str(const char* errorStr, char* argument){
	int length = strlen(errorStr) + strlen(argument) + 1;
	char* buf = (char*) Calloc(1, length);
	sprintf(buf, errorStr, argument);
	return buf;
}

char* fillString(const char* string, char* argument){
  return fill_error_str(string, argument);
}


char* trim(char* String){
	if(! String) return String;

	char* start = String;
	char* end = String + strlen(String) - 1; //Subtract 1 to move back from the null pointer

	for(; *end == ' ' || *end == '\r' || *end == '\n' || *end == '\t'; *end--='\0');
	for(; *start == ' '; start++);

	return start;
}

bool isInteger(char* str){

	for(char* start = str; *start !='\0'; start++){
		if(*start < '0' || *start > '9') return false;
	}

	return true;
}



	static char* prev_addr;
char* strtok2_O(char* buffer, char* delim){
		
		//if(! buffer) prev_addr = buffer;
		if(!buffer && !prev_addr) return NULL; //There are no continuations and no string, leave
		if(!buffer && prev_addr) buffer = prev_addr; //Continuing


		char* token, *returnVal = buffer;
		char* end = buffer;
    bool isFound = false;


		for(token = end; *end !='\0' && (end=strstr(token, delim)); end = end + strlen(delim)){
			
      //(end) = *(end + 1) = '\0'; //Delete the CR_LF
      for(size_t i =0 ; i< strlen(delim);i++){
        *(end + i) ='\0';
      }

			if(end && end != token){ //If its not null and the needle isn't at the beginning of the string
				returnVal = trim(token);
				prev_addr = end + strlen(delim);
        isFound = true;
				debug("Parsing comand trimmed %s|\n", returnVal);
				break;
			}
			else{
				error("Input was malformed!\n");
				
			}
						
		}


    if(! isFound){
        prev_addr = NULL;
    }

		return returnVal;

}


int getMidtermGrade(sem_t * sem){

    int* value = calloc(1, sizeof(int));

    if(sem_getvalue(sem, value)){
        error("There was a problem getting the Midterm Grade!\n");
    } 

    int returnVal = *value;
    free(value);

    return returnVal;
}


char * findSession(char* arguments){
    const char* delim = " ";
    char *session, *token;

    if((session = strstr(arguments, SESSION_PREFIX))){//SESSION Found
        if((token = strtok(session, delim))){ //Nothing in front of the session
             debug("Still arguments left after session?\n");
              debug("%s\n", token + strlen(token) + 1);
        }
        else{
            token = session;
        }

        token = trim(token); //Remove any additional whitespace around it
        session = token;
        debug("Found Session ID! %s\n", session);
    }
    else{ // SESSION_NOT_FOUND
        error("Session not found in response!\n");
        return NULL;
    }

    return session;
}




char * generateRandomSession(char* alphabet, int length){
  //debug("Generating %d random characters\n", length);
  int alpha_length = strlen(alphabet);
  char* buffer = Calloc(1, length + 1);
  strcat(buffer, SESSION_PREFIX); 
  for(int i = strlen(SESSION_PREFIX) ; i < length; i++){
      int random = rand();
      int index = (((char) random >> 2)  % alpha_length); //Get the lower 8 bits and mod it with the length of the alpha
      if(index < 0) index = ~index + 1;
      //debug("Adding character %c for index %d\n", *(alphabet + index), index);
      *(buffer + i) = *(alphabet + index); //Pick the character at random genearated index and insert into buffer
  }
  *(buffer + length) = '\0'; 

  debug("Generated Random Session %s\n", buffer);
  return buffer;
}

/**************************** WRAPPER CLASSES *****************************************/
pid_t forkProcess(){
  pid_t returnVal;
  //multiThreadDebug("Forking!\n");

  if((returnVal = fork()) < 0){
    error("Error trying to fork a process : %s\n", strerror(errno));
    exit(EXIT_FORKFAIL);
  }
  else{
    //multiThreadDebug("Forked Successfully!\n");
  }

  return returnVal;
}


int Send(int socketfd, char *buf){
        int charSent = -1;
        if ((charSent = send(socketfd,buf, strlen(buf),0))== -1  || errno == EPIPE){
            if(errno == EPIPE || errno == EINTR || errno == SIGPIPE || errno == EBADF)
            {
              error("Something went wrong \n");
              //Close(socketfd);
              //exit(EXIT_FAILURE);
            }
            error("Failure Sending Message\n");
        }
          // int fd = OpenIgnoreMode(FILE, O_CREAT | O_WRONLY | O_APPEND);
          // // debug("%d characters where set through send\n",charSent);
          // Write(fd,buf,strlen(buf));
          // Close(fd);
          debug("%s was sent to the sever\n",buf);
          
          
        return charSent;
}
int Connect(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  int success;
  if( (success=connect(sockfd,addr,addrlen)) == -1)
  {
    std_error("Something went wrong with the connection\n");
    Close(sockfd);
    exit(EXIT_FAILURE);
  }
  if(errno == EPIPE || errno == EINTR || errno == SIGPIPE || errno == EBADF || errno == ECONNREFUSED)
  {
    error("Something went wrong closing connections\n");
    Close(sockfd);
    exit(EXIT_FAILURE);

  }

  return success;

}
int Select(int fd, fd_set *fdset){
    int bitsSets;
    if( (bitsSets = select(fd, fdset, NULL, NULL, NULL)) == -1 ) 
    {
      error("something went wrong when trying to find the open bit"); 
      if(errno == EPIPE || errno == EINTR || errno == SIGPIPE || errno == EBADF || errno == ECONNREFUSED)
      {
        error("Something went wrong closing connections\n");
        verbose("don't know how to handle this");
        // isClientRunning = false;
        FD_ZERO(fdset);
        Close(fd);
        exit(EXIT_FAILURE);

      }
    }



  return bitsSets;
}

int OpenFileCurrentDirIgnoreMode(const char *file, int flags){
    
    char* current = (char*) file;
    if(! strstr(file, "/")){
        char buffer[MAX_PATH];
        memset(buffer, 0, MAX_PATH);
        char * current = getcwd(buffer,MAX_PATH);
        strcat(current, "/");
        strcat(current, file);
    }

    return OpenIgnoreMode(current, flags);
}

int OpenFileCurrentDir(const char* file, int flags, mode_t mode){
     char* current = (char*) file;
    if(! strstr(current, "/")){
      char buffer[MAX_PATH];
      memset(buffer, 0, MAX_PATH);
      current = getcwd(buffer,MAX_PATH);
      strcat(current, "/");
      strcat(current, file);
    }
    return Open(current, flags, mode);
}

int OpenIgnoreMode(const char *file, int flags){

  int returnVal;
  if((returnVal = open(file, flags)) < 0){
      error("Error Opening File : %s --> %s\n", file, strerror(errno));
  }

  return returnVal;
}

int Open(const char* file, int flags, mode_t mode){

  int returnVal;
  if((returnVal = open(file, flags, mode)) < 0){
      error("Error Opening File : %s --> %s\n", file, strerror(errno));
  }

  return returnVal;
}

ssize_t Read(int fd, void* buf, size_t count){
  ssize_t returnVal;
  if((returnVal = read(fd, buf,count)) < 0){
      error("Error Reading from File %s\n", strerror(errno));
  }
  return returnVal;
}


ssize_t Write(int fd, const void* buf, ssize_t count){
  ssize_t returnVal;
  if((returnVal = write(fd, buf,count)) < 0){
      error("Error Writing to File %s\n", strerror(errno));
  }
  else if(returnVal != count){ 
      error("Write to file failed. Expected %zu bytes but got %zd\n", count, returnVal);
  }
  return returnVal;
}

int Close(int fd){
  int returnVal;
  if((returnVal = close(fd)) < 0){
      error("Error closing File %s\n", strerror(errno));
  }
  return returnVal;
}

void CloseAll(int in_fd, int out_fd, int backFile, int inputFile){
    if(backFile != -1)
      Close(backFile);
    if(inputFile != -1)
      Close(inputFile);
    if(in_fd != -1)
      Close(in_fd);
    if(out_fd != -1)
      Close(out_fd);
}

off_t Lseek(int fd, off_t offset, int whence){

    off_t totalOffset;
    /* Set the file position*/
    if((totalOffset = lseek(fd, offset, whence)) < 0) {
        /* failed to move the file pointer */
        error("Problem moving the cursor forward/back %lu bytes", offset);
        exit(EXIT_FAILURE);       
    }

    return totalOffset;
}

void* Calloc(size_t nitems, size_t size){
    void* ptr;

    if(! (ptr = calloc(nitems, size))){
        error("There was a problem Calloc'ing space!\n");
    }

    return ptr;
}





/*****************************END WRAPPER CLASSES********************************/


int ReadBuffer(int fd, char inputBuf[]) {

      int count = 0;
      char *cursor;

      debug("%d",fd);
      // for(count = 0, cursor = inputBuf, last_char = 1; last_char != '\n';cursor++, count++) 
        //{  
            cursor = fgets(cursor = inputBuf, MSG_BUFFER, stdin);
            debug("Read %s\n", cursor);
          
            //*cursor = *symbol;
            
    //	}
            /*
      if(count > 1) {
      	*(--cursor) = '\0';
      	count--;
      }*/
      return count;
}

/*****************************COLOR BUILDING FUNCTION********************************/

char *Build_Message(const char *color,char *msg){

   char *color_buf = Calloc(1,strlen(color) + strlen(DEFAULT_COLOR) + strlen(msg) + 1);
   
   strcat(color_buf,color);
   strcat(color_buf,msg);
   strcat(color_buf,DEFAULT_COLOR);

   return color_buf;

 }

/*****************************END COLOR BUILDING FUNCTION********************************/


/*****************PPrint Methods ***************************/


void printSessionList(uNodeP users){

  uNodeP start, head;
  start = head = users;
  verbose("PrintSesions!");

  do
  {
    if(! start) break;
    if(! start->user) break; 

    debug("User : %s | Session : %s\n", start->user->name, start->user->session);

    start = start->next;
  }while(start && start != head);

  verbose("END PrintSesions!");
}

void printDescriptor(ePollP arr, int length){

  verbose("PRINT Descriptors!");

	debug("FD Count : %d\n", length);

	for(int i=0; i < length; i++){
		ePollEvent poll = *(arr + i);
    debug("___________________________\n");
		debug("FD:%d\n", poll.data.fd);
    debug("Events: %d\n", poll.events); 
    debug("___________________________\n");
	}


  verbose("END PRINT Descriptors!");
}


void printUserList(uNodeP head){

  verbose("PrintingUserList!");

	uNodeP start = head;


	if(! head){
		verbose("END PrintingUserList! : --> List is Empty!");
		return;
	}

	do
	{	//debug("Adding User! %d\n",  (int)start->user->room);
		if(! start->user){ debug("Error! no User! --> FAIL"); break;}
		printUser(start->user);
		start = start->next;
	}while(start && start != head);

  verbose("END PrintingUserList! : Success");
}

void printUser(userP user){

    verbose("User!");
    debug("\t Name : %s\n", user->name);
    debug("\t FD : %d\n", user->fd);
    debug("\t isLoggedIn : %d\n", user->isLoggedIn);
    debug("\t isAuthenticating : %d\n", user->isAuthenticating);
    
    if(user->room){
      debug("\t Chatroom : %s\n", user->room->name);
      debug("\t Chatroom ID : %d\n", user->room->id);
    }        

    verbose("END User!");


}

void printChatrooms(chatNodeP head){

    chatNodeP start = head;

    verbose("Printing Chatrooms!");

    if(! start){
      verbose("END - Printing Chatrooms : No chatrooms!");
      return;
    }

    do
    {
      printChatroom(start->room);
      start = start->next;
    }while(start && start != head);

    verbose("END -> Printing Chatrooms!");
}

void printChatroom(chatroomP chatroom){

		verbose("Chatroom!");
		debug("\t ID %d\n", chatroom->id);
		debug("\t Name %s\n", chatroom->name);
		debug("\t NumUsers %lu\n", chatroom->numOfUsers);
		if(chatroom->admin)
			debug("\t Admin %s", chatroom->admin->name);

    if(chatroom->users){
        uNodeP start,head ;
        start = head = chatroom->users;
        verbose("\tUsers");

        do
        {
          if(! start->user){debug("No Users!\n");break;}
          debug("\t\tUser : %s\n", start-> user->name);
          start = start->next;
        }while(start && start != head);

        verbose("\tEnd Users");
    }
    
    verbose("END Chatroom!");

} 

void printMessageQueue(echoP messages){

  verbose("Printing Messages!");
  echoP start = messages; 

  if(! start){debug("No Messages!\n"); verbose("");return;}

  do
  {

    debug("Echo : %s\n", start->message);
    start = start -> next;
  }while(start && start != messages);

   verbose("END Printing Messages!");
}


/*************** END Print MEthods ***************************/



/*************** Struct Creation ***************************/


userP createUserStruct(int fd){
  userP tempUser = Calloc(1, sizeof(User));
  tempUser -> fd = fd;

  return tempUser;
}

userP createUser_helper(int fd, char* name, chatroomP chatroom){
    verbose("CreateUser_helper!");
    userP user = createUserStruct(fd);
    user->name = name;
    user->room = chatroom;
    verbose("END CreateUser_helper!");
    return user;
}

uNodeP createUserNode(userP user){
  verbose("CreateUserNode!");
  uNodeP node = Calloc(1, sizeof(UserNode));
  node-> user = user;
  node->prev = node-> next = node;
  verbose("END CreateUserNode!");
  return node;
}

passP createPassP(unsigned char* buffer, int length, unsigned char* salt){

  passP mHash = Calloc(1, sizeof(Password));

  mHash -> buffer = buffer;
  mHash -> length = length;
  mHash -> salt = salt;

  return mHash;
}

uNodeP createTempNode(userP user){
  debug("Started Creating the temp node!!\n");

  uNodeP node = createUserNode(user);
  node->isFreeable = true;

  debug("Success! Created the temp node!!\n");
  return node;
}

uNodeP createTempUserAndNode(int fd){


  userP tempUser = createUserStruct(fd);
  tempUser -> isFreeable = true;

  uNodeP node = createTempNode(tempUser);

  return node;
}

nodeDataP createAddUReturnNode(uNodeP head){
  nodeDataP returnValue = Calloc(1, sizeof(AddUNodeData));
  returnValue->headOfList = head;

  return returnValue;
}


chatroomP createChatP(userP adm, char * name){
    
    chatroomP chatroom = Calloc(1, sizeof(Chatroom));

    if(adm){
      uNodeP node =  createUserNode(adm);
      chatroom -> users = node;
      adm -> room = chatroom;
    }
    

    chatroom -> name = name;
    chatroom -> numOfUsers = 1;
    chatroom -> admin = adm;
    

    return chatroom;
}


chatNodeP createChatroomNode(chatroomP chat){

  chatNodeP node = Calloc(1, sizeof(ChatroomNode));
  node->room = chat;

  return node;
}


echoP createEcho(const char* command, char* msg){
  verbose("CREATE ECHO!");

  debug("Creating echo for %s --> %s\n", command, msg);
  echoP echo = Calloc(1, sizeof(Echo));

  int length = strlen(command) + strlen(CR_LF) + 2; //VERB_CRLF\0

  if(msg){
    length = length + strlen(msg) + 1; //VERB_msg_CRLF\0
  }

  char* buffer = Calloc(1, length);

  strcat(buffer, command);
  strcat(buffer, " ");

  if(msg){
    strcat(buffer, msg);
    strcat(buffer, " ");
  }
  
  strcat(buffer, CR_LF);

  echo->message = buffer;

  debug("Created Echo for %s\n", buffer);
    
  verbose("END CREATE ECHO! --> Sucess!");  
  return echo;
}

echoP createPrivateEcho(const char* command, char * msg){
  echoP echo;
  if(! (echo = createEcho(command, msg))){
    error("Problem creating private echo for %s\n", command);
    return NULL;
  }
  //debug("Created Private Echo!\n");
  echo->isPrivate = true;
  return echo;
}

connP createConnP(Socket clientAddr){
    connP connection = Calloc(1,sizeof(Connection));
    connection->connAddr = clientAddr;
    return connection;
}


userP copyUser(userP src){
    userP userName = createUserStruct(src->fd);

    if(! userName){
      error("There was a problem copying the User!\n!");
    }

    userName->name = src->name;
    userName->room = src->room;
    userName->isFreeable = src->isFreeable;
    userName->isAuthenticating = src->isAuthenticating;
    userName->isLoggedIn = src->isLoggedIn;
    userName->password = src->password;


    return userName;
}

char* copyString(char* src){
    char* userName = Calloc(1, strlen(src) + 1);

    if(! userName){
      error("There was a problem copying the string\n!");
    }
    strcat(userName, src);

    return userName;
}

char* buildEchoString(char* name, char* msg){

    char* newString = Calloc(1, strlen(name) + strlen(msg) + 2); //name_msg\0

    strcat(newString, name);
    strcat(newString, " ");
    strcat(newString, msg);

    return newString;
}


bool FreeInputAndReturn(char* input, bool returnVal){
  verbose("Free Input and Return!");

  free(input);

  verbose("END --> Free Input and Return!");
  return returnVal;
}
/************************************************************/





/******************** DB STUFFZZ ******************************/



int prepareSQLStmt(const char* stmt, sqlite3_stmt** response){
    int rv;
        
    if ((rv = sqlite3_prepare_v2(userDatabase, stmt, -1, response, 0)) != SQLITE_OK) {
        
        error("Failed to prepare stmt: %s\n", sqlite3_errmsg(userDatabase));
        sqlite3_close(userDatabase);
        return -1;
    }    

    return 0;
}

int fetchNextStatement(sqlite3_stmt* response){
    int rv;

    if((rv = sqlite3_step(response))!= SQLITE_ROW){
        debug("Fetching next Statement --> Returned Value : %d!\n", rv);
        return rv;
    }
    else{
        debug("_____________________________________________________________\n");
        debug("Found Statement Column 0! %s,\n", sqlite3_column_text(response, 0));
        debug("Found Statement Column 1! %s,\n", sqlite3_column_text(response, 1));
        debug("Found Statement Column 2! %s\n", sqlite3_column_text(response, 2));
        debug("_____________________________________________________________\n");
        return SQLITE_ROW;
    }
}



bool createUserTable(){

  sqlite3_stmt *res;
  bool isComplete = true;

  if(prepareSQLStmt(SQL_STMTS[CREATE_USRTABLE], &res) < 0){
        error("Failed to insert Password, Error Preparing Statement!\n");
        return false;
  }

  if(fetchNextStatement(res) != SQLITE_OK){
        error("Failed to Insert Password\n");
        isComplete = false;
  }

  sqlite3_finalize(res);

  return isComplete;
}

bool createPassTable(){


  sqlite3_stmt *res;
  bool isComplete = true;

  if(prepareSQLStmt(SQL_STMTS[CREATE_PASSTABLE], &res) < 0){
        error("Failed to CreatePassTable, Error Preparing Statement!\n");
        return false;
  }

  if(fetchNextStatement(res) != SQLITE_OK){
        error("Failed to Insert Password\n");
        isComplete = false;
  }

  sqlite3_finalize(res);

  return isComplete;
}



bool InsertUser(userP user){

  if(!isDBInitialized) return false;

    sqlite3_stmt *res;
    bool isComplete = true;

    if(! InsertPassword(user->password)){
        error("There was a problem inserting the password, User not being inserted...\n");
        return false;
    }


    if(prepareSQLStmt(SQL_STMTS[INSERT_USER], &res) < 0){
        error("Failed to insert User, Error Preparing Statement!\n");
        return false;
    }

    sqlite3_bind_int(res, 1, (int) user);
    sqlite3_bind_text(res, 2, user->name, strlen(user->name), 0);
    sqlite3_bind_int(res, 3, (int)user->password);

    if(fetchNextStatement(res) != SQLITE_OK){
        error("Failed to Insert User %s\n", user->name);
        isComplete  = false;
    }
    else{
        debug("Succesfully Inserted User! --> %s\n", user->name);
    }
     

    sqlite3_finalize(res);

    return isComplete;
}


bool InsertPassword(passP pass){

  if(!isDBInitialized) return false;

  sqlite3_stmt * res;
  bool isComplete = true;

  if(prepareSQLStmt(SQL_STMTS[INSERT_PASS], &res) < 0){
        error("Failed to insert Password, Error Preparing Statement!\n");
        return false;
  }

  sqlite3_bind_int(res, 1, (int) pass);
  sqlite3_bind_int(res, 2, pass->length);
  sqlite3_bind_blob(res, 3, pass->buffer, pass->length, SQLITE_STATIC);
  sqlite3_bind_blob(res, 3, pass->salt, MAX_SALT, SQLITE_STATIC);

  if(fetchNextStatement(res) != SQLITE_OK){
        error("Failed to Insert Password\n");
        isComplete = false;
  }

  sqlite3_finalize(res);

  return isComplete;
}


bool updateUserAddress(userP user, int oldVal){

  if(!isDBInitialized) return false;
    char* str = Calloc(1, strlen(SQL_STMTS[UPDATE_ADDRESS]) + strlen(USER_TABLE) + 1);
    sprintf(str, SQL_STMTS[UPDATE_ADDRESS], USER_TABLE);
    bool returnVal = Update(str,(int) user, oldVal);
    free(str);
    return returnVal;
}


bool updatePassAddress(passP pass, int oldVal){
  if(!isDBInitialized) return false;
    char* str = Calloc(1, strlen(SQL_STMTS[UPDATE_ADDRESS]) + strlen(PASS_TABLE) + 1);
    sprintf(str, SQL_STMTS[UPDATE_ADDRESS], PASS_TABLE);
    bool returnVal = Update(str, (int) pass, oldVal);
    free(str);
    return returnVal;
}


bool Update(char* query, int newValue, int oldValue){

  sqlite3_stmt *res;
  bool isComplete = true;

  if(!isDBInitialized) return false;

  if(prepareSQLStmt(query, &res) < 0){
        error("Failed to Update, Error Preparing Statement!\n");
        return false;
  }

  sqlite3_bind_int(res, 1, newValue);
  sqlite3_bind_int(res, 2, oldValue);

  if(fetchNextStatement(res) != SQLITE_OK){
        error("Failed to Insert Password\n");
        isComplete = false;
  }

  sqlite3_finalize(res);

  return isComplete;
}

passP fetchPassword(int addr){

  sqlite3_stmt *res;
  passP returnVal = NULL;

  if(!isDBInitialized) return false; 

   if(prepareSQLStmt(SQL_STMTS[SELECT_PASS], &res) < 0){
        error("Failed to Update, Error Preparing Statement!\n");
        return NULL;
  }

  sqlite3_bind_int(res, 1, addr);

  if(fetchNextStatement(res) != SQLITE_ROW){
        error("Failed to Insert Password\n");
  }
  else{
      debug("Returned Pass Succesful!\n");  
      
      int length = sqlite3_column_int(res, 2);
      unsigned char * buf = (unsigned char*) sqlite3_column_blob(res, 3);
      unsigned char* salt = (unsigned char*) sqlite3_column_blob(res, 4);
      returnVal = createPassP(buf, length, salt);
  }

  sqlite3_finalize(res);

  debug("Still here?");
  printpassP(returnVal);
  return returnVal;
}

void reloadUsers(){

/*
  if(!isDBInitialized) return;
  int rv;
  char *err_msg;

  if((rv = sqlite3_exec(userDatabase, SQL_STMTS[SELECT_ALL_USER], addUsersFromDB, 0, &err_msg)) != SQLITE_OK){
      error("SQL error Reloading Users! : %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(userDatabase);
  }
*/
}




bool InitializeDatabase(){
    int rv;
    bool isCreated = true;

    if( access( DB_FILE, F_OK ) < 0) {
      isCreated = false;
      debug("DB File doesn't exist, creating it...\n");
    } 

    if ((rv = sqlite3_open_v2(DB_FILE, &userDatabase, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL)) != SQLITE_OK) {
        
        error("Cannot open database: %s\n", sqlite3_errmsg(userDatabase));
        sqlite3_close(userDatabase);
        std_error("Error! There was a problem initializing user database, data will not be persistent!\n");
        return false;
    }

    if(! isCreated){
        bool createUsers = createUserTable();
        bool createPass = createPassTable();

        if(! createUsers || ! createPass){
          error("there was a problem initializing the tables! %d:%d\n", createUsers, createPass);
          return false;
        }
    }
    
    debug("Autocommit: %d\n", sqlite3_get_autocommit(userDatabase));

    return true;
}

/*
int addUsersFromDB(void *ignore, int argc, char ** argv, char **azcolName){

    ignore = 0;
    azcolName= 0;
    debug("Total args : %d", argc);

    char* addr = argv[1];
    if(! addr) return 0;
      char* name = argv[1];
      if(! name) return 0;
      char* passString = argv[2];
      if(!passString) return 0;
      passP pass = fetchPassword(atoi(passString));

      userP tempUser = Calloc(1, sizeof(User));
      tempUser->name = name;
      tempUser->password = pass;
      tempUser->fd = -1;
      tempUser -> room = waitingRoom;

      if(isSessionEnabled){
        tempUser -> session = generateRandomSession(SESSION_ALPHABET, SESSION_SIZE);
      }
      uNodeP newUser = createUserNode(tempUser);
      addUserNode(allUsers, newUser);

      updateUserAddress(tempUser, atoi(addr));
      updatePassAddress(pass, atoi(passString));
      return 0;
  }
  */
/**************************************************************/
