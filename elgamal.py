import random

# Implementation of ElGamal Cryptographic System
class ElGamal:

  #Function 'power' calculates (a^b)mod(m) efficiently using binary exponentiation
  def power(self,a,b,m):
    ans=1
    while b>0:
      if b&1: ans=(ans*a)%m
      a=(a*a)%m
      b>>=1
    return ans

  #Function used for genarating key by receiving side
  def generate_key(self, q, alpha):
    # q is a prime number
    # alpha<q and is a primitive root of q 

    # Select 1<X_A<q-1
    X_A=random.randint(2,q-2)
    # Calculate Y_A = (alpha^X_A) mod(q)
    Y_A=self.power(alpha,X_A,q)

    # private_key=X_A
    PR=X_A
    # public_key= [q,alpha,X_A]
    PU=(q,alpha,Y_A)

    #return private key and public key
    return PR,PU

  #Function to encrypt a message M<q using public key PU
  def encrypt(self,M,PU):

    # Unpack parameters q, alpha and Y_A from public key
    (q,alpha,Y_A) = PU
    # select 1<k<q
    k= random.randint(2,q-1)
    # Calculate K=(Y_A^k)mod(q)
    K= self.power(Y_A,k,q)
    # Calculate C1=(alpha^k)mod(q)
    C1= self.power(alpha,k,q)
    # Calculate C2=(KM)mod(q)
    C2= (K*M)%q

    #return cypher text as (C1,C2)
    C=(C1,C2)
    return C

  #Function to decrypt a cypher text C using public key PU and private key PR
  def decrypt(self,C,private_key,public_key):
    
    # Unpack C1 and C2 from cypher text C
    (C1,C2) = C
    # Unpack parameters q, alpha and Y_A from public key
    (q,alpha,Y_A) = public_key
    X_A = private_key

    # Calculate K^(-1) = (C1^(q-1-X))mod(q)
    K_inverse = self.power(C1,q-1-X_A,q)
    # Decypher message M=(C2*(K^(-1)))mod(q)
    M= ( C2*K_inverse )%q

    return M

elGamal=ElGamal()

# Value of parameters
q,alpha=107,5

# Key Generation
private_key,public_key=elGamal.generate_key(q,alpha)

print("We have implemented ElGamal Algorithm for integers")

# Message m<q
message=34
print(f"Original message is {message}")

# Encryption using public key
cipher_text=elGamal.encrypt(message,public_key)
print(f"Encrypted cypher text is {cipher_text}")

# Decryption using public key and private key
decrypted_text=elGamal.decrypt(cipher_text,private_key,public_key)
print(f"Decrypted text is {decrypted_text}")
