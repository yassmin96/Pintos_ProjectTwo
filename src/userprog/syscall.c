#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "kernel/console.h"
#include "list.h"

/* Process identifier type. */
typedef int pid_t; 

static void syscall_handler (struct intr_frame *);
static bool valid_user_prog_ptr(const void* ptr);
static void get_params(int* ptr, int* params[], int count);
static void halt(void);
static struct file_process* get_file_mapped(int fd);
static bool create_file(const char *file, unsigned initial_size);
static bool remove_file(const char *file);
static int open_file (const char *file);
static void close_file(int fd);
static int read_file(int fd, void *buffer, unsigned size);
static int write_file (int fd, const void *buffer, unsigned size);
static unsigned tell_file (int fd);
static void seek_file (int fd, unsigned position);
static int filesize (int fd);
static int wait_for_child(pid_t pid);
static void exit (int status);
static tid_t exec (const char *cmd_line);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{

//================>>> Our implementation <<<==========================//

 int* stack_ptr = (int *)f->esp;

 /* Checks whether valid pointer reference. */
 if(!valid_user_prog_ptr(stack_ptr))
    exit(-1);

 int* params[4];

switch(*stack_ptr)
{    
    case SYS_HALT:                                /* System Call HALT. */
       halt();
       break;               
    case SYS_EXIT:                                /* System Call EXIT. */
      get_params(stack_ptr, params, 1);
      exit (*params[0]);
      break;                  
    case SYS_EXEC:                                /* System Call EXEC. */
      get_params(stack_ptr, params, 1);
      f->eax = exec ((char *)*params[0]);
      break;                   
    case SYS_WAIT:                                /* System Call WAIT. */                 
      get_params(stack_ptr, params, 1);
      f->eax = wait_for_child (*params[0]);
      break;                                  
    case SYS_CREATE:                              /* System Call CREATE. */
      get_params(stack_ptr, params, 2);
      f->eax = create_file((const char*)*params[0], *((unsigned*)params[1]));    
      break;                
    case SYS_REMOVE:                              /* System Call REMOVE. */
      get_params(stack_ptr, params, 1);
      f->eax = remove_file((const char*)*params[0]);
      break;                
    case SYS_OPEN:                                /* System Call OPEN. */
      get_params(stack_ptr, params, 1);
      f->eax = open_file((const char *)*params[0]);
      break;                 
    case SYS_FILESIZE:                            /* System Call FILESIZE. */
      get_params(stack_ptr, params, 1);
      f->eax = filesize(*params[0]);
      break;             
    case SYS_READ:                                /* System Call READ. */
      get_params(stack_ptr, params, 3);
      f->eax = read_file(*params[0], (void *)(*params[1]), *((unsigned*)params[2]));
      break;                   
    case SYS_WRITE:                               /* System Call WRITE. */
      get_params(stack_ptr, params, 3);
      f->eax = write_file(*params[0], (const void *)(*params[1]), *((unsigned*)params[2]));
      break;                  
    case SYS_SEEK:                                /* System Call SEEK. */
      get_params(stack_ptr, params, 2);
      seek_file(*params[0], *((unsigned*)params[1]));   
      break;                  
    case SYS_TELL:                                /* System Call TELL. */
      get_params(stack_ptr, params, 1);
      f->eax = tell_file (*params[0]);
      break;                 
    case SYS_CLOSE:                               /* System Call CLOSE. */
      get_params(stack_ptr, params, 1);
      close_file (*params[0]);
      break;
    default:
        exit(-1);
        break;   
   }
}


/* Checks whether pointer is a valid pointer reference within process page directory. */
static bool
valid_user_prog_ptr(const void* ptr)
{
  if(ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
      return true;

  return false;
}

/* Extracts params out of stack. */
static void
get_params(int* ptr, int* params[], int count)
{
  int i;
  bool terminate = false;
  for(i = 1; i <= count; i++){

       int* curr_ptr = ptr + i;
       if(!valid_user_prog_ptr((const void*)curr_ptr)){

          terminate = true;
          break;

       }
     params[i - 1] = curr_ptr;  
     
  }
  if(terminate)
     exit(-1);
}


/* Terminates Pintos by calling shutdown_power_off()*/
static void
halt(void) {  
  shutdown_power_off();
}


/*Terminates the current user program, returning status to the kernel.
 If the process's parent waits for it, this is the status that will be returned.
 Conventionally, a status of 0 indicates success and
 nonzero values indicate errors. */
static void
exit (int status)
{
  struct thread* current_thread = thread_current();
  
  current_thread->exit_state = status;
  if(current_thread->parent_thread != NULL) {

  	struct list_elem *e; 
  	for (e = list_begin (& current_thread->parent_thread->child_process); 
                e != list_end (& current_thread->parent_thread->child_process);      
           	e = list_next (e))
         	{
              		struct child_thread* child = list_entry(e, struct child_thread, child_elem);
              
              		if(child->child_tid == current_thread->tid){
                 		child->exit_state = status;
                	        break;
              	        }
                }
  }
  thread_exit();
}


/* Runs the executable whose name is given in cmd_line, 
   passing any given arguments, and returns the
   new process's program id (pid). Must return pid -1, 
   which otherwise should not be a valid pid, if the
   program cannot load or run for any reason. Thus, the parent process
   cannot return from the exec until it knows whether the child process
   successfully loaded its executable. You must use appropriate
   synchronization to ensure this. */
static tid_t
exec (const char *cmd_line) {

 /* Checks whether valid string. */
 if(!valid_user_prog_ptr((void*) cmd_line))
     exit(-1);

 struct thread* current_thread = thread_current();
 current_thread->is_child_loaded_successfully = false;

 tid_t child_pid = process_execute(cmd_line);

 sema_down(&current_thread->loaded_successfully);

 if(!current_thread->is_child_loaded_successfully)
     return -1;


 return child_pid;
}



/* Waits for a child process pid and retrieves the child's exit status.
   If pid is still alive, waits until it terminates. Then, returns the 
   status that pid passed to exit. If pid did not call exit(), but was
   terminated by the kernel (e.g. killed due to an exception), wait(pid)
   must return -1. wait must fail and return -1 immediately if any of 
   the following conditions is true:
   => pid does not refer to a direct child of the calling process.
   => The process that calls wait has already called wait on pid. 
      That is, a process may wait for any given child at most once. */
static int 
wait_for_child(pid_t pid) {
   return process_wait(pid);
}


/* Creates a new file called file initially initial_size bytes in size.
   Returns true if successful, false otherwise.
   Creating a new file does not open it: opening the new file is
   a separate operation which would require a open system call. */
static bool
create_file(const char *file, unsigned initial_size)
{ 
   if(!(valid_user_prog_ptr((void*) file)))
	exit(-1);

   file_sys_lock_acquire();
  
   bool success = filesys_create(file,initial_size);
    
   file_sys_lock_release();

   return success;
}

/* Deletes the file called file. Returns true if successful, false otherwise. 
   A file may be removed regardless of whether it is open or closed, and removing
  an open file does not close it. */
static bool
remove_file(const char *file)
{
   file_sys_lock_acquire();
  
   bool success = filesys_remove (file); 
    
   file_sys_lock_release();
   return success;
}


/* Opens the file called file. Returns a nonnegative integer handle called 
   a "file descriptor" (fd), or -1 if the file could not be opened.
   File descriptors numbered 0 and 1 are reserved for the console:
   fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is 
   standard output. The open system call will never return either of
   these file descriptors, which are valid as system call arguments
   only as explicitly described below.
   Each process has an independent set of file descriptors.
   File descriptors are not inherited by child processes.
   When a single file is opened more than once, whether by a single 
   process or different processes, each open returns a new file descriptor.
   Different file descriptors for a single file are closed independently in
   separate calls to close and they do not share a file position. */
static int
open_file (const char *file) 
{
   if(!(valid_user_prog_ptr((void*) file)))
	exit(-1);

   file_sys_lock_acquire();
   
   struct file* file_open = filesys_open (file);
   
   file_sys_lock_release();
   
   if(file_open == NULL || file == NULL) 
	return -1;
	

   struct file_process *file_o = malloc (sizeof(struct file_process));
   
   file_o->file = file_open;

   struct thread* current_thread = thread_current();
   int file_descriptor = current_thread->fd_count;
   
   current_thread->fd_count++;
   file_o->fd = file_descriptor;
   list_push_back (&current_thread->opened_files, &file_o->elem);

   return file_descriptor;
}



/* Returns the size, in bytes, of the file open as fd. */
static int
filesize (int fd) {

   struct file_process* file = get_file_mapped(fd);
 
   file_sys_lock_acquire();
   
   int file_size = (int) file_length (file->file);  
   
   file_sys_lock_release();

   return file_size;
}



/* Reads size bytes from the file open as fd into buffer. 
   Returns the number of bytes actually read (0 at end of file),
   or -1 if the file could not be read (due to a condition other 
   than end of file). Fd 0 reads from the keyboard using input_getc(). */
static int
read_file(int fd, void *buffer, unsigned size)
{  
  
   if(!(valid_user_prog_ptr(buffer)))
       exit(-1);

   if(fd == 0) {
     int i;
     uint8_t *buffer = (uint8_t*) buffer; 
  
     for (i = 0; i < (int)size; i++) {
         *buffer =  input_getc();
          buffer =  buffer + 1;
     }

     return size;

   } else {

     struct file_process* file = get_file_mapped(fd);

     if(file == NULL)
         return -1;

     file_sys_lock_acquire();
     off_t len =  file_read (file->file,buffer,(off_t) size);
     file_sys_lock_release();

     return len;
   }  
}

static struct file_process*
get_file_mapped(int fd)
{
  //struct list opened_files = thread_current()->opened_files;
  struct list_elem *e;  
  for (e = list_begin (&thread_current()->opened_files); e != list_end (&thread_current()->opened_files);
           e = list_next (e))
         {
            struct file_process* file = list_entry(e, struct file_process, elem);
            if(file->fd == fd)
                return file;     	
         }
   return NULL;
  
}




/* Closes file descriptor fd. Exiting or terminating a process 
   implicitly closes all its open file descriptors, as
   if by calling this function for each one. */
static void
close_file(int fd) {
   struct file_process* file = get_file_mapped(fd);

   if(file == NULL)
  	exit(-1);

   file_sys_lock_acquire();

   file_close (file->file);

   file_sys_lock_release();

   list_remove(&file->elem);

   free(file);
}



/* Writes size bytes from buffer to the open file fd. Returns the number
   of bytes actually written, which may be less than size if some bytes 
   could not be written. Writing past end-of-file would normally extend the file, 
   but file growth is not implemented by the basic file system. 
   The expected behavior is to write as many bytes as possible up to end-of-file and return
   the actual number written, or 0 if no bytes could be written at all.
   Fd 1 writes to the console. */
static int
write_file (int fd, const void *buffer, unsigned size)
{
 
  if(!(valid_user_prog_ptr(buffer)))
	exit(-1);



  if (fd == 1) { //writes to the console
     putbuf (buffer, (size_t) size);
     return size;
   } else {
     struct file_process* file = get_file_mapped(fd);

     if(file == NULL)
         return 0;

     file_sys_lock_acquire();
     off_t len = file_write (file->file,buffer, (off_t) size);
     file_sys_lock_release();

     return len;
   }  
}

/* Changes the next byte to be read or written in open 
   file fd to position, expressed in bytes from the
   beginning of the file. (Thus, a position of 0 is the file's start.) */
static void 
seek_file (int fd, unsigned position) {
   
   struct file_process* file = get_file_mapped(fd);
   
   file_sys_lock_acquire();
   
   file_seek (file->file, position);
   
   file_sys_lock_release();

}

/* Returns the position of the next byte to be read or written
  in open file fd, expressed in bytes from the beginning of the file. */
static unsigned
tell_file (int fd) {
   
   struct file_process* file = get_file_mapped(fd);

   if(file == NULL)
  	return -1;

   file_sys_lock_acquire();
  
   unsigned offset = (unsigned) file_tell(file->file); 
    
   file_sys_lock_release();

   return offset;
}


