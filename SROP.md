# SROP
## Intro
Sigreturn Oriented Programming (SROP) is an exploitation technique that takes advatange of a sigreturn to ultimatly control code execution.

### Signals
To understand how/why SROP works, we first need to know about signals. A signal is a software interrupt delivered to a process. Depending of the signal, it will have vairous affects on the program. Most signals will halt program execution though. Without knowing it, you have most likely invoked many signals during daily use of your OS. When you hit `ctrl + c` to kill a program, you are sending a **SIGINT** signal to the program. The default reaction to a **SIGINT** signal is killing the application. There are also synchronous singals like **SIGSEGV** and **SIGABRT** that you have probably seen during exploitation of buffer overflows.

### Signal Handlers
All signals have some default behaviour. But a program can create a signal handler to alter the response to receiving certain signals. Have you ever tried to `ctrl + c` when using the GDB and nothing happened? That is because GDB catches the signal with a signal handler and does not choose to exit the program. A signal handler can be implemented like this:

```c
void signal_handler(int x)
{
	printf("SIGINT received, but I'm not leaving!\n");
}

int main()
{
	signal(SIGINT, signal_handler);			// Register the handler
	while(1);
}
```

This program enters an infinite loop, and when the user tries to kill the program with `ctrl + c`, it prints **SIGINT received, but I'm not leaving!** But how does this work? We know that when the program enters the infinite loop, it is stuck executing `jmp` over and over to itself. Something behind the scenes has to happen for it to suddenly shift code execution to the signal handler, then back to the infinite loop, when a signal is received.

### The Internals
What happens hear is that the Kernel takes over and sets up the execution of the signal handler. Specifically, the Kernel pushes a **signal frame (sigframe)** to the stack in userspace that has all the information needed for the program to resume exectuion after the signal handler. This includes the values of general purpose registers, segment registers, floating-point registers, vector registers and alot more. 

This signal frame is defined at [/arch/x86/include/asm/sigframe.h](https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/sigframe.h)

```c
struct rt_sigframe {
	char __user *pretcode;
	struct ucontext uc;
	struct siginfo info;
	/* fp state follows here */
};
```

Since `rt_sigframe` has alot of nested memebers, we will only be going over the parts important for SROP. The first member of `rt_sigframe` is `char __user *pretcode` which is a function pointer to `__restore_rt` which has the following code:

```
<__restore_rt>:		mov    rax,0xf
<__restore_rt+7>:	syscall
```

Syscall 0xf is `rt_sigreturn`. This sounds familiar, seems like it will be important in SROP. The [man page](https://man7.org/linux/man-pages/man2/sigreturn.2.html) for `rt_sigreturn` explains it best:

> If the Linux kernel determines that an unblocked signal is
 pending for a process, then, at the next transition back to user
 mode in that process (e.g., upon return from a system call or
 when the process is rescheduled onto the CPU), it creates a new
 frame on the user-space stack where it saves various pieces of
 process context (processor status word, registers, signal mask,
 and signal stack settings).
The kernel also arranges that, during the transition back to user
 mode, the signal handler is called, and that, upon return from
 the handler, control passes to a piece of user-space code
 commonly called the "signal trampoline". The signal trampoline
 code in turn calls sigreturn().
This sigreturn() call undoes everything that was done—changing
 the process's signal mask, switching signal stacks (see
 sigaltstack(2))—in order to invoke the signal handler. Using the
 information that was earlier saved on the user-space stack
 sigreturn() restores the process's signal mask, switches stacks,
 and restores the process's context (processor flags and
 registers, including the stack pointer and instruction pointer),
 so that the process resumes execution at the point where it was
 interrupted by the signal.
 
 `rt_sigreturn` is responsible for resuming program execution after the signal handler. The next member of the `rt_sigframe` that we will look at is `struct ucontext uc`. It is defined at [l/include/uapi/asm-generic/ucontext.h](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/ucontext.h)
 
 ```c
struct ucontext {
	unsigned long uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	struct sigcontext uc_mcontext;
	sigset_t uc_sigmask; /* mask last for extensibility */
};
 ```
 
 And we are interested in `struct sigcontext uc_mcontext;` as it holds all the general pupose registers which we will be using during exploitation. It is defined at [/arch/x86/include/uapi/asm/sigcontext.h](https://github.com/torvalds/linux/blob/master/arch/x86/include/uapi/asm/sigcontext.h)
 
 ```c
struct sigcontext {
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 rdi;
	__u64 rsi;
	__u64 rbp;
	__u64 rbx;
	__u64 rdx;
	__u64 rax;
	__u64 rcx;
	__u64 rsp;
	__u64 rip;
	__u64 eflags; /* RFLAGS */
	__u16 cs;
	__u16 gs;
	__u16 fs;
	union {
		__u16 ss; /* If UC_SIGCONTEXT_SS */
		__u16 __pad0; /* Alias name for old (!UC_SIGCONTEXT_SS) user-space */
	};
	__u64 err;
	__u64 trapno;
	__u64 oldmask;
	__u64 cr2;
	struct _fpstate __user *fpstate; /* Zero when no FPU context */
 ```
 
 When `rt_sigreturn` is called, the kernel takes these values from the stack in userspace and places them into their respective registers (not all the memebers of `sigcontext` are register values).
 
 All of this combined is how the kernel and program go about invoking a signal handler when needed.
 
 ## Exploitation
 
 Since there are no checks in place that verify that the sigframe was created by the kernel, could it be possible to forge a sigframe then call `rt_sigreturn`? That would be a really powerful because it would allow an attacker to controll every register allowing them to have alot of control of code execution. And this is exactly what SROP is.
 
 With a BOF, we can place a fake sigframe on the stack with the `sigcontext` struct containing the register values that we would like, then call `rt_sigreturn` to pop all those values into the appropriate registers, shifting code execution to whatever the attacker wants. 
 