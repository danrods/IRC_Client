#include "aloha.h"

volatile sig_atomic_t stop_signal = 0;
volatile sig_atomic_t echo_signal = 0;

void signal_interrupt(int sig){
	sigset_t mask, prev;
  	synchronizeFull(&mask, &prev);
	stop_signal = 1; //Signal the others~
  	atomic_write("Int!\n",5);
	
	endSynchronize(&prev);
	sig++;
}

void sig_wake_echo(int sig){
	sigset_t mask, prev;
  	synchronizeFull(&mask, &prev);
  	echo_signal = 1;
  	//atomic_write("Wakey Wakey\n", 12);
  	endSynchronize(&prev);
  	sig++;
}

lambda_t* SignalFunc(int signalNum, lambda_t* handler){
  
  struct sigaction action, old_action;

  action.sa_handler = handler;
  sigemptyset(&action.sa_mask); /* Block sigs of type being handled */
  action.sa_flags = SA_NODEFER;

  if(sigaction(signalNum, &action, &old_action) < 0){
      multiThreadDebug("Error signaling From Signal : %d\n", signalNum);
  }

  return (old_action.sa_handler);
}