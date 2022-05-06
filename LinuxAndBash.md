# Linux

In this section, we will start learning Linux. Linux is often referred to as an operating system.
You are already familiar with operating systems whether you know it or not. In fact, you are
using one right now! An operating system (OS) can be thought of as the computers manager. It
is the most important software that runs on a computer because it manages the computer’s
memory, processes, and other software. The most popular OS’s are Microsoft Windows and
macOS.

So where does Linux fall into play and what makes it different? Well, Linux isn’t your typical, run
of the mill OS. Actually, Linux isn’t necessarily an OS but a kernel. A kernel is often said to be
the heart of the OS.

#### Analogy:
- We might think of a computer as a store. In this case, the OS would be the boss. Their
job is to run the store by controlling its operations.
- We could then consider a kernel the boss’s personality, which dictates who he works
well with, the guidelines and policies he implements, how he chooses to decorate and
even which language he speaks.
- Now, let’s imagine this business as a family-owned business and their last name is Linux.
There’s Kali Linux, Debian Linux, Ubuntu Linux, and several others. Each of them runs
several different stores, but they all work similarly because they all have the same
personality type.

Considering this analogy, you can see that Linux isn’t just an operating system, but instead the
personality of several different operating systems. There are hundreds of distributions of Linux,
and even Android and macOS also use kernels that are very similar.
To put these lessons to use, you might want to go ahead and install one of these Linux
distributions on your computer or a virtual machine.

#### Quiz:

What is an operating system?
- a. Someone who builds computers 
- b. The computer’s hardware
- c. The computer’s manager 
- d. A fancy way of saying computer

What is a kernel?
- a. Popcorn seed 
- b. The heart of the OS
- c. A storefront that runs Linux 
- d. A person

Now that we have a general idea of what Linux is, let’s start learning how to use it. To use any
OS, you need to give it commands to tell it what to do. You are probably familiar with clicking
buttons and dragging things around on the screen to tell your OS what operations to perform.
When you do this, you are using what is called the graphical user interface (GUI, pronounced
gooey). You might be thinking, I don’t want to use a GUI anymore, that sounds disgusting. If
that is the case, you are in luck. There is another way to give your OS commands and it is
through the command-line interface (CLI). Instead of clicking buttons with the GUI, to use the
CLI you type commands to tell the OS what actions to perform.

This is where the shell comes into play. The shell is a program that takes the commands you
type in the CLI and sends them to the OS to perform. There are several different shells that
accept slightly different commands, but for this course, we will focus on one called bash
(Bourne Again shell).

Most Linux distributions will default to the bash shell. Depending on which distribution you’re
working with, the shell prompt might change slightly. But, for the most part, it should be
something along these lines:

username@hostname:current_directory

joe@uca:/home/joe $

The prompt comes with the $, you don’t have to add it. It just means a normal user using Bash.
For the remainder of the lessons, I will include a $ to indicate the beginning of a command, but
just remember you don’t have to type it.

Let’s start with the most basic command, which just prints whatever text you type behind it.

$ echo Hello World

What does this command print to the display?
  a. Hello World 
  b. echo Hello World
  c. $ echo Hello World 
  d. username@hostname:current_directory

Let’s talk about files. Everything in Linux is a file AKA directory. You put files in files, and they
are arranged in a hierarchical tree. The very beginning directory of this tree is called the root
directory and contains all the files. It is the starting point from which all the other directories
branch out of. And is indicated with a /. To change directories in the CLI you can type the
command cd. Let’s try changing to our root directory.

$ cd /

Did it work? How can we tell? We can use the pwd command to print the location of our
current directory. Pwd stands for print working directory.

$ pwd

The location of a directory is called its path. The path starts with the root symbol (/) then
separates the following directories with the same symbol (/). An example might be
/home/joe/Photos. This is the path of Joe’s Photos directory.

Let’s change from our root directory into another directory. First, we need to check to see
which files we have stored in our root directory. We can do that with the list command,
denoted by ls.

$ ls

See all those files? Now let’s use what we’ve learned so far to change into one of them.

$ cd /home

#### Quiz

Did it work? How can we tell?
- a. $ cd / 
- b. $ pwd
- c. $ ls 
- d. $ cd /home
  
What is a path?
- a. The base directory 
- b. a hierarchical tree
- c. $ ls 
- d. a files location
