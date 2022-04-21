# Stack and Heap

## Static Memory

Static memory is memory that is allocated during compile time, which is the time when the programmer is writing the code.

This memory allocation is fixed and cannot be modified during run time. Let’s see an example:

figure1

In this example, we see that an array is declared with four elements. You can see that this array has a fixed size and cannot be increased or decreased during run time.

There are a few issues with static memory allocation that should be addressed before moving on:
- The size of allocated memory is fixed at the time of declaration and cannot be adjusted by the user at run time.
- Memory is wasted when the values stored by the user at run time are less than the specified size.
- The program may crash if the values stored by the user at run time are more than the specified size.

Static memory is allocated or deallocated in a defined order in the stack. This is done automatically by the compiler.

## Stack

A stack is an area of a computer’s memory that stores temporary variables created by a function. When calling a new function, room on the stack is allocated for the functions automatic and temporary variables. This newly allocated space is called a stack frame, which are like blocks of data that get pushed onto the top of the stack for each function call.

It should be noted that variables in the stack are declared, stored, and initialized during runtime. This means that the size of a stack frame is calculated when the program is compiling. Although, these values are decided by the programmer and cannot be changed at run time by the user. Let’s look at an example to understand further.

figure2

We know that the main() function is always the first function called in a program. When the main() function is called, memory is automatically allocated on the stack to make room for the function’s temporary variables. These variables are stored in a stack frame.

figure3

We can see that the memory space for this stack frame isn’t allocated until the program is compiling and the function is called. This orange stack frame will remain in the stack until the main function is finished running.

We can observe that the main() function calls the Add() function. As previously stated, when a new function is called, memory for the temporary variables in that function is allocated to the stack. Let’s see that in action.

figure4

The new stack frame containing the variables for the Add() function is pushed onto the existing stack frame from main(). In this program, the Add() function is passed two numbers then returns the sum of their values to main(). Once the Add() function is finished, it’s stack frame is popped off the stack.

figure5

Notice that we have completed the Add() function and it’s stack frame is no longer on the stacks memory. This de-allocation of memory happens automatically as soon as the function completes its execution. However, since we are not yet done executing the main() function, its stack frame can still be seen on the stack memory. When the main() function finishes, it’s stack frame will also be popped off automatically, the program will be terminated, and the console will return the output.

figure6

## Dynamic Memory

Dynamic memory allocation is the process of allocating memory at the time of execution, which lets users allocate memory according to their needs. This is done using pointers, which play a huge role in dynamic memory allocation.

Dynamic memory allocation differs from static memory allocation is several ways. Dynamic memory allocation is not automatic. There are a few built-in functions that help allocate or deallocate memory space at run time. malloc() realloc() and free() are examples of these functions, which we’ll see in use later in this lesson.

Dynamic memory allocation is stored in a random, unordered location in the heap, not ordered in the stack like static memory allocation.

## Heap

The heap is the area in memory where the dynamic allocation usually takes place. The memory is allocated during the execution of a program’s instructions. The heap area is shared by all shared libraries and dynamically loaded modules in a process. Let’s look at an example to better understand.

figure7

In this program, you can see that a pointer *x has been created and allocates dynamic memory using the malloc() function. We pass the malloc() function the size of an integer, which tells it to reserve four bytes of random, contiguous memory in in the heap. Once this block of memory is reserved successfully, the pointer is returned pointing to the first byte of the allocated memory.

This number is 200 in the example below.

figure8

Once malloc() returns the beginning address of the allocated block in memory, we can use typecasting to store an element in that address. You can see this carried out in the figure below.

figure9

If we want to then remove that same variable from memory address 200, we can use the built-in function free() as seen below.

figure10

I have marked out the value 100 here to show the action taking place, but the free() function empties the block completely. We can then use the same pointer as before to allocate memory in a new location, to store another variable. Check out the example below.

figure11

## Summary

At this point, you should understand the difference between the stack and the heap. Let’s summarize these differences by comparing the two.

figure12

## Quiz 

Where does dynamic memory allocation usually take place?  
  a. Stack  
  b. Heap  
  c. Stack Frame  
  d. Heap Frame

Variables stored in the stack can be changed by the user at run time (T/F)  
  a. True   
  b. False  

