#ifndef ALOHA_H
#define ALOHA_H
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sched.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <semaphore.h>
#include <pthread.h>
#include <poll.h>
#include <sqlite3.h>
#include <sys/epoll.h>
// #include "threadpool.h"

// #ifdef GUIACTIVE
//     #include <gtk/gtk.h>
// #endif


#define MAX_INPT  1024
#define MAX_LINE 8192
#define MAX_ARRAY_SIZE 8133
#define MAX_PATH    128
#define MAX_HISTORY 
#define MAX_CONN 1024
#define BUFFER_SIZE 512
#define MSG_BUFFER_MIN 1000
#define MSG_BUFFER 1001
#define MAX_PROC    64
#define MAX_EVENTS 16
#define ALPHABET 128 /*Alphabet consist of [a-z,A-Z,0-9]*/
#define BYTE 1
#define MAX_SALT 3
#define MIN_PASS_LENGTH 5
#define TOTAL_ECHO_THREADS 1
#define TOTAL_USER_THREADS 1
#define TOTAL_FD_THREADS 1
#define TOTAL_THREADS = 3 //1 For Listener Thread
#define ALARM_WAIT_TIME 1
#define POLL_TIMEOUT 3500
#define MAX_LISTEN_Q  1024 
#define LINE "----------------------------------------------"
#define CTRLC '\003'
#define CTRLZ '\032'
#define DEL '\177'
#define BACKSPACE '\b'
#define SPACE " "
#define NEWLINE '\n'
#define TAB '\t'
#define isArrow1 '\033'
#define isArrow2 '['
#define UP_ARROW 'A'
#define DOWN_ARROW 'B'
#define RIGHT_ARROW 'D'
#define LEFT_ARROW 'C'
#define continue_sig_message "Continuing...\n" 
#define cont_message_length 14
#define stop_sig_message "Stopping...\n" 
#define stop_message_length 12
#define pause_sig_message "Pausing...\n" 
#define pause_message_length 11
#define exit_sig_message "Exit Success!\n" 
#define exit_message_length 14
#define exit_ab_sig_message "Exit Abnormal!\n" 
#define exit_ab_message_length 15
#define SESSION_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.!@#$%^&*()_+~<>?:{}|"

// #define FILE ".SendHistory.txt"
#define DB_FILE "aloha.db"
#define AUTH_FILE "auth.log"

#define USER_TABLE "User"
#define PASS_TABLE "Password"

#define GUI_FILE "guioutput.txt"



/************* Commands *******************/

//Get Client/Server ai_flags
#define CLIENT_AI_FLAGS  AI_NUMERICSERV | AI_ADDRCONFIG
#define SERVER_AI_FLAGS  AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV

///Server////
#define INTRO_SERVER "!AHOLA"
#define LOGIN_COMPLETE_ACK "HI"
#define LOGIN_AUTH_ACK "AUTH"
#define CREATE_USER_ACK "HINEW"
#define ERROR "ERR"
#define CLOSE_CONN "BYE"
#define ECHO_CMD "ECHO"
#define CREATE_ACK "RETAERC"
#define CREATE_PRIVATE_ACK "PETAERC"
#define LISTROOM_ACK "RTSIL"
#define JOIN_ACK "NIOJ"
#define JOIN_PRIVATE_ACK "PNIOJ"
#define LEAVE_ACK "EVAEL"
#define KICK_ACK "KCIK"
#define CLIENT_KICK_MSG "KBYE"
#define TELL_ACK "LLET"
#define TELL_CLIENT_PREFIX "ECHOP"
#define LIST_USER_ACK "UTSIL"
#define SESSION_PREFIX "ALO~"
////////////


///Client///
#define INTRO_CLIENT "ALOHA!"
#define LOGIN "IAM" //User login
#define PASSWORD "PASS" //password login
#define CREATE_USER "IAMNEW" //Creates new user
#define CREATE_PASS "NEWPASS" //Creates password
#define SEND_MSG "MSG" //Msg Max 1000 bytes, max array size 1001
#define QUIT "/quit"
#define HELP_VERB "/help"
#define CREATER_CLIENT "/creater"
#define CREATER_VERB "CREATER" 
#define CREATE_PRIVATE_CLIENT "/createp"
#define CREATER_PRIVATE_VERB "CREATEP" 
#define LISTROOM_CLIENT "/listrooms"
#define LISTROOM_VERB "LISTR"
#define JOIN_CLIENT "/join"
#define JOIN_VERB "JOIN"
#define JOIN_PRIVATE_CLIENT "/joinp"
#define JOIN_PRIVATE_VERB "JOINP"
#define LEAVE_CLIENT "/leave"
#define LEAVE_VERB "LEAVE"
#define KICK_CLIENT "/kick"
#define KICK_VERB "KICK"
#define TELL_CLIENT "/tell"
#define TELL_VERB "TELL"
#define LIST_USERS_CLIENT "/listusers"
#define LIST_USERS_VERB "LISTU"
#define ERROR_LINE "Error"
///////////

#define SERVER "Server"
#define NO_CHATS "no_rooms -1"
#define KICK_MSG "You have been kicked out of the chat room"
#define ECHO_SEM "Echo"
#define USER_SEM "User"
#define FD_SEM "FD"



///Client enums///

typedef const enum {ALOHA, IAM,IAMNEW, PASS, NEWPASS,HINEW,
                         MSG, _QUIT,CREATER, CREATEP,
                         LISTR, JOIN, JOINP, LEAVE,
                         KICK, TELL, LISTU,HELP,BYE} Protocols;
///////////

#define CR_LF "\r\n"
#define CR_LF_2 "\r\n\r\n"


/************ END COMMANDS ***************/



/********** Escape Colors ****************/
#define INFORMATIVE_COLOR "\x1B[1;34m"
#define ERRORS_COLOR "\x1B[1;31m"
#define PRIVATE_COLOR "\x1B[1;35m"
#define DEFAULT_COLOR "\x1B[0m"
#define ARG_COLOR "\x1B[5;32m"
#define OUTPUT_COLOR "\x1B[5;36m"

#define Build_Private_Message(msg) Build_Message(PRIVATE_COLOR, msg)
#define Build_Error_Message(msg) Build_Message(ERRORS_COLOR, msg)
#define Build_Info_Message(msg) Build_Message(INFORMATIVE_COLOR, msg)
#define Build_Color_Message(color, msg) Build_Message(color, msg)
// #define Build_Message(color, msg) char color_buf[strlen(color) + strlen(DEFAULT_COLOR) + strlen(msg) + 1]; Message_Color(color, msg, buf)
// #define Message_Color(color, msg, buffer) strcat(buffer,color); strcat(buffer,msg); strcat(buffer,DEFAULT_COLOR)

/***********END Escape Color**************/


/********************Struct Library ******************/

typedef struct Chatroom //Serializable
    {
        int id;
        char *name;
        size_t numOfUsers;
        struct Password* password;
        struct User *admin;
        struct UserNode *users;
    } Chatroom, *chatroomP;


typedef struct User //Serializable
    {
        int fd;
        char *name;
        char *session;
        struct Password* password;
        chatroomP room;
        bool isLoggedIn;
        bool isAuthenticating;
        bool isFreeable;

    } User, *userP;


typedef struct Password  //Serializable
    {
        unsigned char * buffer;
        unsigned char * salt;
        size_t length;
    }Password, *passP;


///////////////////////////////////

typedef struct ChatroomNode
    {
        
        chatroomP room;
        struct ChatroomNode* prev;
        struct ChatroomNode* next;

    } ChatroomNode, *chatNodeP;


typedef struct UserNode
    {
        bool isFreeable;
        struct UserNode* prev;
        struct UserNode* next;
        userP user;

    } UserNode, *uNodeP;


typedef struct Echo
    {
        char* message;
        struct Echo * prev;
        struct Echo * next;
        uNodeP users;
        bool isPrivate;
    } Echo, *echoP;

typedef struct AddUserNodeData
    {
        uNodeP headOfList;
        bool isError;
    } AddUNodeData, *nodeDataP;


typedef struct ChatroomData
    {
        chatroomP newRoom;
        int isError;
    } ChatroomData, *chatDataP;


typedef struct Command
    {
        int protocol;
        const char *protocolStr;
        char *arguments;
    } Command, *cmdP;


typedef struct Connection
    {
        int fd;
        struct sockaddr* connAddr;
        socklen_t length;
    }Connection, *connP;


/*****************************************************/



typedef const enum {VERBOSE, DEV, NONE} VERBOSE_LEVEL;
typedef const enum {EXIT_OK, EXIT_FAIL, EXIT_FORKFAIL, EXIT_FNF} RETURN_CODES;
typedef const enum {SIG_HUP=1,SIG_INT=2, SIG_QUIT=3, SIG_KILL=9, SIG_USR1=10, SIG_PIPE=13,
    SIG_ALARM=14, SIG_TERM=15, SIG_CHLD=17,SIG_CONT=18, SIG_STOP=19, SIG_TSTP=20} Signals;
typedef struct Socket_addr_in SocketAddr_in, *Socket_inP;
typedef struct sockaddr SocketAddress, *Socket;
typedef socklen_t SocketLength, *SocketLenP;
typedef struct pollfd  PollFD, *pollP;
typedef void lambda_t(int);
typedef struct epoll_event ePollEvent, *ePollP;

typedef const enum {SORRY, USER_DUP, USER_NF, ROOM_DUP, MAX_ROOM, ROOM_NF, 
                     USER_NOT_PRESENT,NOT_ALLOW, USER_NO, OPERATION_NO, PASSWORD_NO, DEFAULT_ERR, SESSION_INVALID} ERROR_CODES;

typedef const enum {KICKED, LEFT, PROMOTED, JOINED, NEW_ROOM} SERVER_MSGS;

extern char* ERROR_LIST[];
extern size_t SESSION_SIZE;
extern bool isSessionEnabled;
extern bool isGuiActive;

extern VERBOSE_LEVEL DEBUG;
extern bool ECHO_MSG_ONSERVER;
extern bool DEBUG_OVERRIDE;
extern volatile sig_atomic_t stop_signal;
extern volatile sig_atomic_t echo_signal;
extern volatile sig_atomic_t pause_signal;
extern volatile sig_atomic_t parent_done_signal;
extern volatile sig_atomic_t child_done_signal;
extern uNodeP allUsers;
extern chatroomP waitingRoom;


#define this() pthread_self()

#define debug(fmt, ...) if(DEBUG == DEV || DEBUG == VERBOSE || DEBUG_OVERRIDE) fprintf(stdout, "DEBUG: {%lu}  %s ==> (%s:%d) --> " fmt, this(), __FILE__,__FUNCTION__, __LINE__, ##__VA_ARGS__) 
#define error(fmt, ...) if(DEBUG == DEV || DEBUG == VERBOSE || DEBUG_OVERRIDE) fprintf(stderr, "**ERROR: %s:%s:%d " fmt, __FILE__,__FUNCTION__, __LINE__, ##__VA_ARGS__) 
#define verbose(fmt, ...) if(DEBUG == VERBOSE || DEBUG_OVERRIDE) output("\n\n%s" fmt "%s\n\n", LINE, ##__VA_ARGS__, LINE)

#define debugln(fmt, ...) debug("" fmt "\n", ##__VA_ARGS_)
#define output(fmt, ...) fprintf(stdout, "" fmt, ##__VA_ARGS__)
#define std_error(fmt, ...) fprintf(stderr, "" fmt, ##__VA_ARGS__)

#define server_verbosee(fmt, ...) if(ECHO_MSG_ONSERVER) printf("" fmt, ...);

#define multiThreadDebug(fmt, ...) debug("\n-------{P:#%d-->[C:#%d::G:#%d]}-------\n" fmt "%s\n", getppid(),getpid(),getpgid(getpid()),##__VA_ARGS__,LINE)

#define atomic_write(msg, count) if(DEBUG==DEV) Write(1, msg, count);

#define signalChild(id, signal) kill(id, signal)
#define signalGroup(signal) kill(0, signal)//0 --> sig shall be sent to all processes whose process gID is equal to the process group ID of the sender
#define signalGroupPid(id, signal) kill( ((~id) + 1), signal)// -pid  --> sig shall be sent to all processes whose process group ID is equal to the absolute value of pid

#define synchronizeFull(new, old) sigfillset(new); sigprocmask(SIG_BLOCK, new, old)
#define synchronize_single(new, old, Type) sigemptyset(new); sigaddset(new, Type); sigprocmask(SIG_BLOCK, new, old)

#define endSynchronize(old) sigprocmask(SIG_SETMASK, old, NULL)


#define printPromptClient(user) output("%s > server |", user)
#define printPromptServer(user) output("%s < server |", user)
#define printPromptUser(sender, msg, buf) buf = realloc(buf, strlen(buf) + strlen(sender) + 4); sprintf(buf, "%s > %s", sender, msg)


/*int argc, char ** argv, char **envp*/
// int main (int argc, char ** argv, char **envp);
// bool isClientRunning = false;


pid_t forkProcess();
void parse_options(int argc, char** argv);
void batchMode(int rv, int batch_index, char** argv);



// /********************************************************************************************************************************************/


// #ifdef GUIACTIVE
//     GtkApplication *app;
//     GtkWidget *textView;
//     GtkWidget *label;
//     int guiFD;
// #endif


// static void printScreen(char *str)
// {
//   GtkTextBuffer *buffer = gtk_text_view_get_buffer((GtkTextView *)textView);

//   GtkTextIter end;

//   gtk_text_buffer_get_end_iter(buffer, &end);
//   gtk_text_buffer_insert(buffer, &end, str, -1);//writes the string to the view

//   // gtk_text_buffer_get_end_iter(buffer, &end);//writes the newline chartacter
//   // gtk_text_buffer_insert(buffer, &end, "\n", -1);

//   // gtk_text_buffer_get_end_iter (buffer, &end);// attempt to scroll down
//   // gtk_text_view_scroll_to_iter (entry, &end, 0.0, FALSE, 0, 1);
// }

// static void Gui_parseBuffer(GtkEntry *entry)// this will be saving to the file 
// {
//   const char *str;
//   char *sendStr;
//   str =  gtk_entry_get_text (entry);
//   //TODO write code to write this to the file
//   sendStr = calloc(1,strlen(str) + 2);
//   strcpy(sendStr,str);
//   strcat(sendStr,"\n");
//   //TODO write to FILE
//   // if race condition
//   //sleep(2);
//   printf("Before: %d\n", guiFD);
//   guiFD = open("guioutput.txt", O_CREAT | O_RDWR | O_TRUNC, (S_IWUSR| S_IRUSR | S_IXUSR));
//   printf("After: %d\n", guiFD);
//   write( guiFD,sendStr,strlen(str) + 1);
//   close(guiFD);

//   printScreen(sendStr);

//   free(sendStr);

//   gtk_entry_set_text(entry, ""); 

// }

// static void activate (GtkApplication *app)
// {

//   GtkWidget *scrwindow;
//   GtkWidget *window;

//   GtkTextBuffer *buffer;// this is what i'm going to use to display
//   // GtkWidget *button_box;
//   GtkWidget *entryBox;
//   GtkEntryBuffer *entryBuffer;
//   GtkWidget *pane;

//   /********************************** CREATE WINDOW AND MAKE IT SEXY***************/
//   window = gtk_application_window_new (app);
//   gtk_window_set_title (GTK_WINDOW (window), "ShouldveStartedEarlier CHAT");
//   gtk_window_set_default_size (GTK_WINDOW (window), 350, 480);
//   gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
//   /********************************** CREATE WINDOW AND MAKE IT SEXY***************/
  


//   pane = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

//   gtk_container_add (GTK_CONTAINER (window), pane);

//   // this is for the text box for sending shit
//   // view =
//   // button_box = gtk_button_box_new (GTK_ORIENTATION_VERTICAL);
//   // gtk_container_add (GTK_CONTAINER (window), button_box);

//   //init all the widgets in the handler
//   // button1 = gtk_button_new_with_label ("Welcome to Our Chatroom");
//   label = gtk_label_new("Our new Chatroom");
//   // button2 = gtk_button_new_with_label ("THis will be the field the has the chat");
//   textView = gtk_text_view_new ();
//   gtk_text_view_set_editable((GtkTextView *)textView,FALSE);

//   scrwindow = gtk_scrolled_window_new(NULL,NULL);
//   gtk_container_add(GTK_CONTAINER(scrwindow), textView);

//   entryBuffer = gtk_entry_buffer_new (NULL,0);
//   entryBox = gtk_entry_new_with_buffer(entryBuffer);

//   g_signal_connect (entryBox, "activate", G_CALLBACK (Gui_parseBuffer), textView);


//   // gtk_grid_attach( (GtkGrid *) grid, label,240,0, 100,100);
//   gtk_box_pack_start((GtkBox *)pane,label,FALSE,TRUE,4);
//   gtk_box_pack_start((GtkBox *)pane,scrwindow,TRUE,TRUE,2);
//   gtk_box_pack_start((GtkBox *)pane,entryBox,FALSE,TRUE,4);


//   // g_signal_connect (button1, "clicked", G_CALLBACK (print_hello), NULL);
//   // g_signal_connect_swapped (button, "clicked", G_CALLBACK (gtk_widget_destroy), window);
//   // gtk_container_add (GTK_CONTAINER (button_box), button);

//   gtk_widget_show_all (window);
// }

// /*********************************************************************************************************************************************/


/********WRAPPER CLASSES*******************/
int Send(int socketfd, char *buff);
int Select(int fd, fd_set *fdset);
int OpenFileCurrentDirIgnoreMode(const char *file, int flags);
int OpenFileCurrentDir(const char* file, int flags, mode_t mode);
int OpenIgnoreMode(const char* file, int flags);
int Open(const char* file, int flags, mode_t mode);
ssize_t Read(int fd, void* buf, size_t count);
ssize_t Write(int fd, const void* buf, ssize_t count);
int Close(int fd);
void CloseAll(int in_fd, int out_fd, int backFile, int inputFile);
off_t Lseek(int fd, off_t offset, int whence);/*This will move the cursor back*/
/******************************************/


int distinctCount(char* haystack, char* needle);


/********************Signal functions****************/
void signal_interrupt(int sig);

void signal_pause(int sig);

void signal_continue(int sig);

void sig_child(int sig);

void sig_child_main(int sig);

lambda_t* SignalFunc(int signal, lambda_t* handler);

void sig_child_run(int sig);

void sig_wake_echo(int sig);

void createBackgroundProcess();

/***************************************************/

void getCurrentDateStr(char *buff);


int getAddressFD(char* host, char* port);

int client_connectSocket(struct addrinfo *listp);
void client_initHandShake(int client_fd);
char *client_parseBufferUser(char *input);
void client_CreateIRCConnection(int clientfd); 
void client_parseBufferServer(char *input);
void client_executeCallbackResponse(char *command, char *arguments);
bool client_isAckValidFormat(char *response);
bool isCommandValid(int protocol,char *arguments);

bool client_isCommandList(char *response);

int Connect(int sockfd, struct sockaddr *addr, socklen_t addrlen);

char* strtok2_O(char* buffer, char* delim);

char *Build_Message(const char *color,char *msg);

void* server_Listen(void* fd);
void* createConnection(void* ptr);
void* createEchoThread(void*ptr);

char *getProtocol(int protocol);
int getProtocolFromString(char *inputBuf);

int server_fetchBindListenSocket(struct addrinfo* list);
int server_AcceptConnection(int s, Socket socket, SocketLenP addrlen);


char *generateSingleMessage(const char *command);
char *generateMessage(const char *command, char *buffer);

struct addrinfo *Getaddrinfo(char *host, char *port, int flags);
void initiateListener();
void PollInputFDs();
void PollOutputFDs();
void EPollInputFDs();

/********************Command Functions****************/

/* ECHO VERB uses the echop 
 * verb command on all the users*/
echoP createEcho(const char* command, char* msg);
echoP createPrivateEcho(const char* command, char * msg);
bool createPrivateEchoAndEnqueue(const char* command, char* msg, uNodeP user);
bool createEchoAndEnqueue(const char* command, char*msg, uNodeP user);
bool createPrivateEchoFreeAndEnqueue(const char* command, char*msg, uNodeP user);
bool createEchoFreeAndEnqueue(const char* command, char*msg, uNodeP user);
bool createEchoCmdAndEnqueue(char* fromUser, char* arguments, uNodeP toUsers);
bool fillStringCreateEchoCmdAndEnqueue(char* fromUser, char* string, char* args, uNodeP toUsers);

// void CreateRoomCmd(char *name, bool isPrivate);
// void CreateRoomWithPasswordCmd(userP admin,char *name,char *password, bool isPrivate,size_t minUsers);
// void LeaveCmd(userP user);
// bool JoinRoomCmd(int id);
// bool JoinPrivateRoomCmd(int id, char *password);
// /*Returns the file descriptor of the user*/
// int ByeCmd(userP user);
// userP KickUserCmd(chatroomP room, userP user);
// void TellUserCmd(userP fromUser, userP toUser);
// void ListRoomsCmd(userP user);
void echoCmd(char *arguments);
void echoPCmd(char *message);
void listRoomCmd(char *rooms);
void listUsersCmd(char *response);

char **client_parseRooms(char *response);

bool isPrivateRoom(char *response);

void kickCmd();
void ByeCmd();
void printError(char *error);
userP copyUser(userP src);



/*********Server Commands **************/
bool parseInput(int fd, char * input);
chatDataP CreateChatRoom(userP admin, char *name);
chatDataP createPrivateRoom(userP admin, char*name, char* password);
bool closeRoom(chatroomP chatroom);
void KickUser(chatroomP room, userP user);
bool Msg(userP user, char* message);
uNodeP MsgPrivate(userP fromUser, char* toUser);
chatDataP CreateRoom(userP admin,char *name,char *password);
bool Leave(userP user);
chatNodeP findRoom(int id);
bool JoinRoom(userP user, int id);
int JoinPrivateRoom(userP user, int id, char *password);
bool Bye(int fd, userP user);
int kick(userP admin, userP user);
char* ListRooms();
char* ListUsers(userP user);
userP createUser(int fd, char* name);
bool addPassword(int fd, char* password);
bool associatePasswordToUser(userP user, char* password);
bool associatePasswordToChatroom(chatroomP room, char* password);
userP loginStep1(int fd, char* name);
bool loginComplete(int fd, char* password);
/**********END Server Commands**************/

/*****************************************************/

bool validatePassword(char * password);
passP encryptPassword(char* password, unsigned char* salt);
bool comparePassP(passP enc1, passP enc2);
bool comparePasswords(passP encoded, char* password);
unsigned char* generateSalt();
void printMessageQueue(echoP messages);
void printpassP(passP enc);
void printUnsignChar(unsigned char* buf, size_t length);
char * findSession(char* arguments);
char * generateRandomSession(char* alphabet, int length);
/************* Helper Methods *************/
int integerLength(int a);
char* itoa(int i);
char* copyString(char* src);
char* fill_error_str(const char* errorStr, char* argument);
char* fillString(const char* string, char* argument);
char* trim(char* String);
void pass320(sem_t *grade, char* name);
void goOnVacation(sem_t * grade, char* name);
bool start320(sem_t* s,int defaultValue); //Mallocs a new mutex
int getMidtermGrade(sem_t * sem);
void get320ProgressReport();
pthread_t Create_Thread(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int ReadBuffer(int fd,char inputBuf[]);
int Detach_Thread(pthread_t thread);
bool isInteger(char* str);

void getCurrentDateStr(char *buff);
void logUserEntry(uNodeP user,char *error);

userP createUserStruct(int fd);
userP createUser_helper(int fd, char* name, chatroomP chatroom);
uNodeP createTempUserAndNode(int fd);
uNodeP createTempNode(userP user);
uNodeP createUserNode(userP user);
nodeDataP createAddUReturnNode(uNodeP head);
chatNodeP createChatroomNode(chatroomP chat);
chatroomP createChatP(userP adm, char * name);
connP createConnP(Socket clientAddr);
passP createPassP(unsigned char* buffer, int length, unsigned char* salt);
char* copyString(char* src);
char* buildEchoString(char* name, char* msg);
/************* END Helper Methods *************/

ssize_t user_hash(char* message);
ssize_t fd_hash(int fd);

bool putUser(char* name, userP user);
bool putUserFD(int fd, userP user);
userP getUser(char* name);
userP getUserFD(int fd);
void removeUser(int fd);
bool addFD(int fd);
void removeFD(int index);
void removePoll_fd(int fd);
int findFDIndex(int fd);

nodeDataP addUserNode(uNodeP start, uNodeP node);
bool isDuplicateNode(uNodeP start, char* name);
bool isDuplicateChatroom(char* name);
nodeDataP removeUserNode(uNodeP head, userP user);

echoP dequeueMessage();
void enqueueMessage(echoP msg);
bool addChatroom(chatroomP chatroom);
void removeChatroomNode(chatroomP node);
bool addUserToChatroom(chatNodeP chatNode, userP user);

bool FreeChatroom(chatroomP chatroom);
bool FreeEcho(echoP echo);
bool FreeUser(userP user);
bool FreePollP(pollP poll);
bool FreeConnection(connP conn);
bool FreeInputAndReturn(char* input, bool returnVal);
bool FreeChatData(chatDataP data);

void printDescriptor(ePollP arr, int length);
void printUserList(uNodeP head);
void printUser(userP user);
void printChatroom(chatroomP chatroom);
void printChatrooms(chatNodeP head);
void printSessionList(uNodeP users);


void* Calloc(size_t nitems, size_t size);
int CreateEPoll(int flags);
int unblockFD(int fd);
int addEPollFD(int fd);
void removeEPollFD(int index);
int EPollWait(ePollP events, int maxEvents);


/************* Databases **********************/

bool InitializeDatabase();
bool InsertUser(userP user);
bool InsertPassword(passP pass);
int fetchNextStatement(sqlite3_stmt* response);
void reloadUsers();
bool updateUserPassword(userP user);
bool updateUserAddress(userP user, int oldVal);
bool updatePassAddress(passP pass, int oldVal);
bool Update(char* query, int newValue, int oldValue);
int addUsersFromDB(void *ignore, int argc, char ** argv, char **azcolName);
bool createPassTable();
bool createUserTable();
passP fetchPassword(int addr);

/*********************************************/


#define CLIENT_USAGE(name) do {                                                                                             \
        output(                                                                                                             \
            "\n%s [-h] [-c] [-s] NAME SERVER_IP SERVER_PORT \n"                                                             \
            "\n"                                                                                                            \
            "Sends requests to a server that implements the PIRC Protocol \n"                                               \
            "\n"                                                                                                            \
            "Option arguments:\n\n"                                                                                         \
            "-h                             Displays help menu & returns EXIT_SUCCESS.\n"                                   \
            "\n"                                                                                                            \
            "-c                             Requests the server to create a new user.\n"                                    \
            "\n"                                                                                                            \
            "-s                             Tells the program that Session Id is required.\n"                               \
            "\nPositional arguments:\n\n"                                                                                   \
            "NAME                           Username to display when chatting\n"                                            \
            "\n"                                                                                                            \
            "SERVER_IP                      IP address of the server to connect to.\n"                                      \
            "\n"                                                                                                            \
            "SERVER_PORT                    Port to connect to. \n"                                                         \
            ,(name)                                                                                                         \
        );                                                                                                                  \
    } while(0)



    #define SERVER_USAGE(name) do {                                                                                         \
        output(                                                                                                             \
            "______________________________________________________________________________"                                \
            "\n%s [-he] [-N num] PORT_NUMBER MOTD \n"                                                                       \
            "\n"                                                                                                            \
            "Receives requests from clients that implements the PIRC Protocol \n"                                           \
            "\n"                                                                                                            \
            "Option arguments:\n\n"                                                                                         \
            "-h                             Displays help menu & returns EXIT_SUCCESS.\n"                                   \
            "\n"                                                                                                            \
            "-e                             Echo messages received on servers stdout.\n"                                    \
            "\n"                                                                                                            \
            "-N num                         Specifies max number of chatrooms allowed on the server. (default = 5)\n"       \
            "\nPositional arguments:\n\n"                                                                                   \
            "PORT_NUMBER                    Port number to listen on. \n"                                                   \
            "\n"                                                                                                            \
            "MOTD                           Message to display to the client when they connect.\n"                          \
            "\n"                                                                                                            \
            "CONFIG_FILE                    Text file with thread pool values stored in it.\n"                              \
            "______________________________________________________________________________\n"                              \
            ,(name)                                                                                                         \
        );                                                                                                                  \
    } while(0)



#define CLIENT_CMD_HELP() do {                                                                                              \
        output(                                                                                                             \
            "________________Available Client instructions _______________\n"                                               \
            "[/creater] <name>  Command used to create new chatrooms from the waiting room only\n"                          \
            "[/listrooms]         List's all available chatrooms from the waiting room only\n"                              \
            "[/join] <id>         Join a particular chatroom with the id <id> \n"                                           \
            "[/leave]             Leave the chatroom you are in (only works if in a chatroom).\n"                           \
            "[/kick] <username>   Kick the user <username> out of the current chatroom.\n"                                  \
            "[/tell] <user> <msg> Used to send a private message <msg> to user <user>\n"                                    \
            "[/listusers]         List all of the users in a chatroom.\n"                                                   \
            "[/quit]              Will signal server to leave the chatroom, and close connection to server. \n"             \
            "_____________________________________________________________"                                                 \
        );                                                                                                                  \
    } while(0)
