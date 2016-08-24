from MultikeyDGHV_lib import *
import time

#module for testing and benchmarking the MultikeyDGHV scheme
#lmb - is the secure parameter; N - number of the parties; M - array of the messages 
def test(lmb,N,m):
	#generate the parameters based on the secure parameter lambda
	rho=lmb
	eta=(lmb**2)*(N)
	gamma=int(eta**(1.5))
	tau=gamma+lmb
	
	print "%d-bit security level" %lmb


	###########################################
	#Generate N keys:
	start_time = time.time()
	###########################################
	pk = []
	sk = []

	for i in range(0,N):
		sk_tmp,pk_tmp=keygen(eta,tau,gamma,rho)
		sk.append(sk_tmp)
		pk.append(pk_tmp)
	
	print "Secret key - bit-size = %d" %(sk[0].bit_length()) 
	print "Public key - bit-size = %d" %(bit_size(pk[0])) 

	print "Key gen time :"
	print("--- %s seconds ---" % (time.time() - start_time))


	###########################################
	# Encrypt N messages:
	start_time = time.time()
	###########################################	
	c = []
	for i in range(0,N):
		c.append(encrypt(pk[i],m[i],rho))
	

	print "Ciphertext - bit-size = %d" %(c[0].bit_length()) 

	print "Encryption time :"
	print("--- %s seconds ---" % (time.time() - start_time))


	#############################################
	#Re-encrypt N ciphertexts
	start_time = time.time()
	#Generate personal "secret" and Z - parameter for each user
	#############################################

	#Randomly choose the "secret", and generate it for each entity
	secret_index = random.randint(0,N-1)
	secret_key = []
	for i in range(0,N):
		secret_key.append(secret(pk[secret_index]))

	#Generate the additional parameter Z for each user
	Z=[]
	for i in range(0,N):
		Z.append(Z_distribution(gamma,lmb,N,i))

	c_reencrypted = []
	#Re-encrypt each ciphertext
	for i in range(0,N):
		random_noise = noise(rho)	#generate a random noise
		c[i]+=random_noise			#change the ciphertext by the noise
		c_reencrypted.append(reencrypt(Z[i],sk[i],c[i],rho)) 	#re-encrypt the ciphertext with new Z
		c_reencrypted[i]+=secret_key[i]							#add "secret" to the ciphertext


	print "Reencryption for %d users time :" %N
	print("--- %s seconds ---" % (time.time() - start_time))

	#############################################
	#Homomorphical evaluation of the Multiplication operation
	start_time = time.time()
	#############################################

	c_mult = 1
	for i in range(0,N):
		c_mult *= c_reencrypted[i]
	
	print "Joint ciphertext of multiplication - bit-size = %d" %(c_mult.bit_length()) 

	print "Multiplication of %d ciphertexts time :" %N
	print("--- %s seconds ---" % (time.time() - start_time))


	#############################################
	#Homomorphical evaluation of the Summation operation
	start_time = time.time()
	#############################################

	c_add = 0
	for i in range(0,N):
		c_add += c_reencrypted[i]

	print "Joint ciphertext of addition - bit-size = %d" %(c_add.bit_length()) 

	print "Addition of %d ciphertexts time :" %N
	print("--- %s seconds ---" % (time.time() - start_time))


	#############################################
	#Re-decryption of the jointciphertext over the Addition operation
	start_time = time.time()
	#############################################
	
	#Redecrypt the joint ciphertext by removing Zqp, but the "secret" still there
	for i in range(N-1,-1,-1):
		random_noise = noise(rho)	#generate a random noise
		c[i]-=random_noise			#change the ciphertext by the noise
		c_add = redecrypt(sk[i],c[i],c_add,Z[i])

	
	print "Re-decryption of the joint ciphertext under addition for %d users time :" %N
	print("--- %s seconds ---" % (time.time() - start_time))


	#############################################
	#Re-decryption of the jointciphertext over the Multiplication operation
	start_time = time.time()
	#############################################

	#Redecrypt the joint ciphertext by removing Zqp, but the "secret" still there
	for i in range(N-1,-1,-1):
		random_noise = noise(rho)	#generate a random noise
		c[i]+=random_noise			#change the ciphertext by the noise
		c_mult = redecrypt(sk[i],c[i],c_mult,Z[i])


	#print "ciphertext = %d bits" %(c_add.bit_length())

	print "Re-decryption of the joint ciphertext under multiplication for %d users time :" %N
	print("--- %s seconds ---" % (time.time() - start_time))


	#############################################
	#Decryption of the C_add
	start_time = time.time()
	#############################################

	check_add =0
	for i in range(0,N):
		print "message[%d] = %d" %(i+1,m[i])
		check_add ^=m[i]

	for i in range(0,N):
		print m[i], " XOR ",
	print " = ", check_add

	print "Decryption of C_add:"
	print decrypt(sk[secret_index],c_add)
	

	#############################################
	#Decryption of the C_mult
	start_time = time.time()
	#############################################

	check_mult = 1
	for i in range(0,N):
		print "message[%d] = %d" %(i+1,m[i])
		check_mult *=m[i]

	for i in range(0,N):
		print m[i], " x ",
	print " = ", check_mult

	print "Decryption of C_mult:"
	print decrypt(sk[secret_index],c_mult)
	

#############################################
#Main function# Put any values you want below
#############################################
lmb = 5				# Lambda - the secure parameter
N=3					# The number of parties
m=[1,0,0,1,1,1,1]	# The messages for each party
test(lmb,N,m)		# Run encryption under the stated above settings

