#!/usr/bin/python

import random
from Crypto.Util import number
from random import shuffle


from termcolor import colored




def distribution(gamma,rho,sk):
	r=random.randint(2**(int(rho-1)),2**rho)
	q=random.randint((2**(gamma/2)/sk),((2**gamma)/sk))
	return q*sk+r


def Z_distribution(gamma,lmb,N,i):
	#param = random.randint(int((3**i)*gamma*(N-1)*(lmb**(0.01))+i),int((3**i)*gamma*(N-1)*(lmb**(0.03))+i))
	param = random.randint(int((N**i)*gamma*(N-1)*(lmb**0.01)+i),int((N**i)*gamma*(N-1)*(lmb**0.05)+i))
	Z1 = 0
	while (Z1.bit_length()!=param):
		Z1 = random.getrandbits(param)
		if Z1%2==0 : Z1+=1
	print "Z[%d] = %d bits" %(i+1,Z1.bit_length())
	return Z1

def check(x,sk):
	ans = True
	if (x%2==1):
		ans = True
	else:
		ans = False
	if ((x%sk)%2==0):
		ans *= True
	else:
		ans *= False
	return ans


def keygen(eta,tau,gamma,rho):
	sk=number.getPrime(eta)
	pk = []
	for i in range(0,tau+1):
		pk.append(distribution(gamma,rho,sk))
	pk.sort(reverse=True)
	while check(pk[0],sk)!=1:
		for i in range(0,tau+1):
			pk[i]=distribution(gamma,rho,sk)
		pk.sort(reverse=True)
	return sk,pk

def encrypt(pk,m,rho):
	index = []
	rho1=2*rho

	for i in range(1,len(pk)):
		index.append(i)
		
	shuffle(index)

	s=random.randint(1,len(index))
	r=random.randint(1,2**rho1)
	sum_x=0
	for i in range(0,s):
		sum_x+=pk[index[i]]

	#print "R for ciphertext = %d" %r
	#print "2 * Sum_x mod X0 = %d" %(2*sum_x%pk[0])
	#print "2 * Sum_x  = %d" %(2*sum_x)

	c=(m+2*r+2*sum_x)%pk[0]
	return c

def decrypt(sk,c):
	m = (c%sk)%2
	return m 


def reencrypt(Z,pk,m):
	index = []
	
	for i in range(1,len(pk)):
		index.append(i)
		
	shuffle(index)

	s=random.randint(1,len(index))
	sum_x=0
	for i in range(0,s):
		sum_x+=pk[index[i]]

	#print "R for ciphertext = %d" %r
	#print "2 * Sum_x mod X0 = %d" %(2*sum_x%pk[0])
	#print "2 * Sum_x  = %d" %(2*sum_x)

	c=Z*m+(2*sum_x)%pk[0]
	return c


def secret_reencrypt(Z,m,secret_c,sk):
	c = m - m%sk

	c1=m%sk+Z*c+secret_c
	return c1

def secret(pk):
	index = []
	
	for i in range(1,len(pk)):
		index.append(i)
		
	shuffle(index)

	s=random.randint(1,len(index))
	sum_x=0
	for i in range(0,s):
		sum_x+=pk[index[i]]

	#print "R for ciphertext = %d" %r
	#print "2 * Sum_x mod X0 = %d" %(2*sum_x%pk[0])
	#print "2 * Sum_x  = %d" %(2*sum_x)

	c=(2*sum_x)%pk[0]
	return c

def redecrypt(sk,c_o,c_eval,Z):
	m = c_o - c_o%sk
#	print "C_eval beg   = \n%d" %(c_eval)
#	print "Z   = %d" %Z
#	print "Zqp = %d" %(Z*m)
#	print "C_eval - Zqp = \n%d" %(c_eval%(Z*m))
#	if c_eval-Z*m>Z*m : 
#		print "Error: Check size of Z = %d" %Z
#		quit()
	#print "Zpq = %d bits" %((Z*m).bit_length()) 
	return c_eval%(Z*m) 


def test(lmb,N,m):
	rho=lmb
	eta=(lmb**2)*(N)
	gamma=int(eta**(1.5))
	tau=gamma+lmb

	print "Lambda = %d" %lmb
	print "Rho    = %d" %rho
	print "Eta    = %d" %eta
	print "Gamma  = %d" %gamma
	print "Tau    = %d" %tau

#	print "GAMMA = %d" %gamma

	pk = []

	for i in range(0,N):
		pk.append([])
	
	sk = []

	for i in range(0,N):
		sk_tmp,pk_tmp=keygen(eta,tau,gamma,rho)
		sk.append(sk_tmp)
		pk[i].append(pk_tmp)
	
	c = []

	for i in range(0,N):
		c.append(encrypt(pk[i][0],m[i],rho))
	#	print "Ciphertext %d = \n%d" %(i,c[i])
	#	print "Ciphertext %d \nBit-length = %d" %(i,c[i].bit_length())


	#### DEBUG
	noise = []
	q_sk = []

	for i in range(0,N):
		noise.append(c[i]%sk[i]-m[i])
		#print "Noise [%d] = %d " %(i+1,noise[i])
		q_sk.append((c[i]-noise[i])/sk[i])
		#print "Quotient for SK[%d] = %d" %(i+1,q_sk[i])
		#if (c[i]==m[i]+noise[i]+sk[i]*q_sk[i]) : print "True"
	#### END DEBUG


	c_s = []
	c_s = sorted(range(len(c)), key=lambda k: c[k])

	zero_key = c_s.index(min(c_s))

	secret_size = 1
	c_key_zero = []
	c_by_0 = []
	Z=[]

	z_p = []

	for i in range(0,N):
		c_key_zero.append(secret(pk[zero_key][0]))
		secret_size*=c_key_zero[i]

	#### DEBUG
	noise_key_zero = []
	pk_zero =[]
	q_pk_zero =[]

	for i in range(0,N):
		noise_key_zero.append(c_key_zero[i]%sk[zero_key])
		pk_zero.append(c_key_zero[i]-noise_key_zero[i])
		q_pk_zero.append(pk_zero[i]/sk[zero_key])
		#if (c_key_zero[i]==noise_key_zero[i]+pk_zero[i]) : print "OK zero key"
	#### END DEBUG


	for i in range(0,N):
		Z.append(Z_distribution(gamma,lmb,N,i))
		c_by_0.append(secret_reencrypt(Z[i],c[c_s[i]],c_key_zero[i],sk[c_s[i]]))


	c_add = 1
	for i in range(0,N):
		c_add *= c_by_0[i]
		#print "C_mult[%d] = %d bits" %(i+1,c_add.bit_length())

	'''
	#### DEBUG
	print "\n##### DEBUG"
	#t=2
	#if Z[t]*q_sk[c_s[t]]*sk[c_s[t]]>c_by_0[0]*c_by_0[1]*(m[c_s[t]]+noise[c_s[t]]+noise_key_zero[t]+pk_zero[t]) : print "Seems to be OK 3"
	#t=1
	#if Z[t]*q_sk[c_s[t]]*sk[c_s[t]]>c_by_0[0]*(c_by_0[1]-Z[t]*q_sk[c_s[t]]*sk[c_s[t]])*(m[c_s[t]]+noise[c_s[t]]+noise_key_zero[t]+pk_zero[t]) : print "Seems to be OK 2"
	#t=0
	#if Z[t]*q_sk[c_s[t]]*sk[c_s[t]]>(c_by_0[0]-Z[t]*q_sk[c_s[t]]*sk[c_s[t]])*(c_by_0[1]-Z[1]*q_sk[c_s[1]]*sk[c_s[1]])*(m[c_s[t]]+noise[c_s[t]]+noise_key_zero[t]+pk_zero[t]) : print "Seems to be OK 1"

	c_add_check = c_add
	c_by_0_check_upper = 1	
	
	for i in range(N-1,-1,-1):
		c_add_check = redecrypt(sk[c_s[i]],c[c_s[i]],c_add_check,Z[i])
		c_by_0_check = 1
		for j in range(0,i):
			c_by_0_check *= c_by_0[j]
		tmp = c_by_0[i]-Z[i]*q_sk[c_s[i]]*sk[c_s[i]]
		c_by_0_check_upper *= tmp
		if ( c_add_check == c_by_0_check*c_by_0_check_upper) : 
			print colored('Z[%d] decrypt OK','green') %(i+1)
		else: print colored('Z[%d] not decrypted! ERROR!','red') %(i+1)
	
	tmp_check =1 
	for i in range(0,N):
		tmp = (m[c_s[i]]+noise[c_s[i]]+noise_key_zero[i]+pk_zero[i])
		tmp_check *= tmp

	if (c_add_check == tmp_check) : print colored('DECRYPTION IS CORRECT!!!!','green')
	
	#for i in range(0,N):
		#print "m[%d]                = %d" %(i+1,m[c_s[i]])
		#print "noise[%d]            = %d" %(i+1,noise[c_s[i]])
		#print "noise_key_zero[%d]   = %d" %(i+1,noise_key_zero[i])
		#print "pk_zero mod sk_zero = %d" %(pk_zero[i]%sk[zero_key])

	for i in range(0,N):
		print "(%d+%d+%d+%d*%d)*" %(m[c_s[0]],noise[c_s[0]],noise_key_zero[0],q_pk_zero[0],sk[zero_key]),

	noise_track = 1
	for i in range(0,N):
		tmp = m[c_s[i]]+noise[c_s[i]]+noise_key_zero[i]
		noise_track *= tmp

	print colored('\neta   = %d','yellow') %eta
	print colored('gamma   = %d','green') %gamma
	print colored('noise = %d','yellow') %(noise_track.bit_length())
	if (noise_track.bit_length()>=eta) : 	print colored('NOISE GREATER THAN ETA!!!','red')

	#print "Cipher mod sk zero = %d" %(c_add_check%sk[zero_key])

	print "\n##### END DEBUG"
	#for i in range(0,N):
		#if (c_by_0[i]==m[c_s[i]]+noise[c_s[i]]+Z[i]*q_sk[c_s[i]]*sk[c_s[i]]+noise_key_zero[i]+pk_zero[i]) : print "C_by_0 is OK" 
		#if (c_key_zero[i]==noise_key_zero[i]+pk_zero[i]) : print "OK zero key"
	#### END DEBUG
	'''


	for i in range(N-1,-1,-1):
		c_add = redecrypt(sk[c_s[i]],c[c_s[i]],c_add,Z[i])

	print "ciphertext = %d bits" %(c_add.bit_length())

	return (c_add%sk[zero_key])%2


##########################################


lmb=12 #4 by test
N=3
m=[1,1,0,0,1]#,0,1,0,1,0]
m_c=m[0]+m[1]+m[2]

#if test(lmb,N,m)==1 : print "OK"

c = 0
while (test(lmb,N,m)==0):
	c += 1
	print  colored('\n##########################################\nIteration = %d','red') %c

		
'''
c = 0
for i in range(0,100):
	if test(lmb,N,m)==0: c+=1
print "Success = %d" %c

'''
