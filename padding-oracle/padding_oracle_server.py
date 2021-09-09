# we'll be using the lovely pycryptodome library for our crypto functions
from Crypto.Cipher import AES

# for key/iv generation
import random

# since we're using AES for our example, this is 16 bytes
BLOCK_SIZE = 16

# let's set up the 'server-side' functions. our server is going to do the following:
#   - generate a random key (16 bytes). this is kept hidden from the 'attacker'
#   - generate a random IV (16 bytes). this is known to the 'attacker'.
#   - pad the plaintext to prep it for encryption
#   - encrypt the plaintext and provide the attacker with the ciphertext
#
# after it has done those, the 'server' will be supplied with ciphertexts. it will
# decrypt them with its known key and then validate the padding. it will then let
# the 'attacker' know if the padding is valid or not. based on this information, 
# the 'attacker' will be able to methodically decrypt the entire plaintext, without
# ever knowing what the key is
class Server:
    def __init__( self ):
        self.__cipher_key = bytes( [random.randint(0,255) for i in range(16)] )
        self.__cipher_iv = bytes( [random.randint(0,255) for i in range(16)] )
        
        self.__secret_message = "hiya"

    def __encrypt_message( self, plaintext ):
        # boilerplate to set up AES from pycryptodome
        cipher = AES.new( self.__cipher_key, AES.MODE_CBC, iv=self.__cipher_iv )
        
        # remember: before we encrypt, we have to make sure it's properly padded!
        padded_plaintext = self.__pad_plaintext( plaintext )
        
        return cipher.encrypt( padded_plaintext )
        
    # okay, so technically pycryptodome has a built-in padding function, but since
    # we're learning all of this together, i might as well illustrate how it works
    # with some hand-written code.
    def __pad_plaintext( self, plaintext ):
        # figure out how many padding bytes we need for our block size
        num_padding_bytes = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
        
        # remember - we add a whole block of padding if our plaintext is an even
        # increment of BLOCK_SIZE
        if num_padding_bytes == 0:
            num_padding_bytes = BLOCK_SIZE
        
        # then we just append that many bytes with that value to the end of our plaintext. we're also
        # taking the liberty of ensuring that our plaintext is encoded in utf-8 as a binary string
        # for easier handling with the concatenation, etc.
        return plaintext.encode( 'utf-8') + bytes( [num_padding_bytes for i in range(num_padding_bytes)] )

    # again, technically the crypto lib we're using has a build-in padding/validation
    # function, but where's the fun in that? this will spit out a straight true/false on
    # whether padding's valid or not
    def __is_valid_padding( self, ciphertext, submitted_iv ):
        # step 1 is to decrypt the ciphertext using the known key/iv.
        cipher = AES.new( self.__cipher_key, AES.MODE_CBC, iv=submitted_iv )
        plaintext = cipher.decrypt( ciphertext )
        
        # since all padding bytes are the same value, we start with the last byte of the
        # decrypted plaintext, and go from there
        num_padding_bytes = plaintext[-1]
        
        # so, there are several conditions where padding is invalid:
        
        # 1. padding ranges from 0x01 bytes to BLOCK_SIZE bytes
        if num_padding_bytes < 0x01 or num_padding_bytes > BLOCK_SIZE:
            return False
            
        # 2. every padding byte must have the same value - the number of bytes padded
        for i in range( 1, num_padding_bytes+1 ):
            if plaintext[-i] is not num_padding_bytes:
                return False
                
        # if both of those conditions are passed, we know the padding is valid. and this
        # is where a normal system would then strip that padding and return the plaintext
        return True

    # now let's create some functions for the 'attacker' to use. the only things they are
    # going to touch are these three functions. to get the original ciphertext, the IV, and
    # then to submit ciphertexts to be evaluated by the oracle. the oracle will return a true/false
    # on whether padding is valid - and that's it.
    def get_original_ciphertext( self ):
        return self.__encrypt_message( self.__secret_message )
        
    def submit_ciphertext( self, ciphertext, submitted_iv ):
        return self.__is_valid_padding( ciphertext, submitted_iv )
        
    def get_cipher_iv( self ):
        return self.__cipher_iv