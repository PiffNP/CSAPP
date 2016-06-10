#By ZYW
from random import *
import time
import os

while 1:
	N=100
	MAXDATA=1024
	MAXADR=100
	now=time.localtime()
	timestr=str(now.tm_hour)+str(now.tm_min)
	name='test'+timestr+'.ys'
	name2='test'+timestr+'.yo'
#print name
	data=open(name,'w')
	data.write('.pos 0\n')
	data.write('irmovl $0x2000, %ebx\n')
#random read write test
	for i in range(200):
		data.write('irmovl $%d, %%eax\n'% randint(0,MAXDATA))
		data.write('rmmovl %%eax, %d(%%ebx)\n'% (4*randint(1,MAXADR)))
		data.write('mrmovl %d(%%ebx),%%ecx\n'% (4*randint(1,MAXADR)))
#focused read write test on (ebx)
	for i in range(100):
		data.write('irmovl $%d, %%eax\n'% randint(0,MAXDATA))
		data.write('rmmovl %eax, (%ebx)\n')
		data.write('mrmovl (%ebx),%ecx\n')
#sequential read write test
	for i in range(100):
		data.write('irmovl $%d, %%eax\n'% randint(0,MAXDATA))
		data.write('rmmovl %%eax, %d(%%ebx)\n'% (4*i))
		data.write('mrmovl %d(%%ebx),%%ecx\n'% (4*i))
	data.close()
	break