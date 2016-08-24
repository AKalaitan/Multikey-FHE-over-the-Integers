import random
from Crypto.Util import number
from random import shuffle

#Distribution for the public key generation
def distribution(gamma,rho,sk):
	r=random.randint(2**(int(rho-1)),2**rho)
	q=random.randint((2**(gamma/2)/sk),((2**gamma)/sk))
	return q*sk+r

#Distribution for a layer encryption
def Z_distribution(gamma,lmb,N,i):
	param = random.randint(int((N**i)*gamma*(N-1)*(lmb**0.01)+i),int((N**i)*gamma*(N-1)*(lmb**0.05)+i))
	Z1 = 0
	while (Z1.bit_length()!=param):
		Z1 = random.getrandbits(param)
		if Z1%2==0 : Z1+=1
	return Z1

#check even or odd
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

#Generate private and public keys
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

#Standard encryption
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

	c=(m+2*r+2*sum_x)%pk[0]
	return c

#Standard decryption
def decrypt(sk,c):
	m = (c%sk)%2
	return m 

#, with random elements from the Public key

#Returns random even number
def noise(rho):
	return (2*random.randint(1,2**(rho+1)))


#Re-encryption of a ciphertext with new Z from the Z distribution
def reencrypt(Z,sk,ciphertext,rho):
	c = ciphertext - ciphertext%sk  #extract the current q*sk, and store it.
	r = noise(rho)					#take new random noise
	c1=ciphertext%sk+r+Z*c 			#Calculate new ciphertext, with Zqp and new noise
	return c1

#Samples random "secret" based on the provided public key
def secret(pk):
	index = []
	
	for i in range(1,len(pk)):
		index.append(i)
		
	shuffle(index)

	s=random.randint(1,len(index))
	sum_x=0
	for i in range(0,s):
		sum_x+=pk[index[i]]

	c=(2*sum_x)%pk[0]
	return c


#Remove Zqp from the provided joint ciphertext
#q*sk recalculated in this function, but by the idea, Zqp should be stored along with the secret key on a PC of the user
def redecrypt(sk,c_original,c_eval,Z):
	m = c_original - c_original%sk
	return c_eval%(Z*m) 

#Calculate bit size of the provided object
def bit_size(f):
	count = 0
	for i in range(0,len(f)):
		count +=f[i].bit_length()
	return count
