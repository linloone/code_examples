# so now let's, as an attacker, figure out what the secret message on the server is,
# given just the IV, the ciphertext, and the ability to submit as many ciphertexts as
# we want, with feedback on whether the padding is valid or not

# our Server module
from padding_oracle_server import Server
from padding_oracle_server import BLOCK_SIZE

# pretty-print function to convert those weird-looking bytestrings in python to just a hexstring
def pretty_print_bytestring( bytestring ):
    return ''.join( "{:02x}".format(c) for c in bytestring )

server = Server()

# step 1 is to get the original ciphertext. we need the IV to decrypt the first block;
# the IV is not typically something that is hidden, though it certainly can be, but
# the standards do not require that it is kept away from the client. in this example,
# we will have the ability to fetch the IV. this is common in certain cookies, etc.
# with encrypted data, so that the server itself does not have to store it.
original_ciphertext = server.get_original_ciphertext()
cipher_iv = server.get_cipher_iv()

print( f"Original ciphertext for secret message: {pretty_print_bytestring(original_ciphertext)}" )
print( f"IV supplied by the server: {pretty_print_bytestring(cipher_iv)}" )
print()

# so the way we implement this attack is to start at the last block and then work our way backwards.
# to do that, let's figure out how many blocks are in our ciphertext.
num_ciphertext_blocks = len(original_ciphertext) // BLOCK_SIZE

print( f"Number of ciphertext blocks: {num_ciphertext_blocks}" )
print()

# i'm going to change up how we have the original ciphertext stored to (hopefully)
# make reading the code a bit cleaner. i'm going to split it up into a list of blocks,
# so that addressing individual bytes is done as:
#       original_ciphertext[block_num][byte_num] (zero-indexed, of course!)
original_ciphertext = [ original_ciphertext[block_num*16:(block_num+1)*16] for block_num in range(num_ciphertext_blocks) ]

cumulative_staging = []
cumulative_decoded = []

# and we're gonna work on each block, one at a time, from last block to first
for block_num in range( num_ciphertext_blocks-1, -1, -1 ):
    print( f"== WORKING ON BLOCK: {block_num} ==" )
    
    # we only need two consecutive blocks to perform this attack. so we take the current
    # block and its previous one.
    current_block = original_ciphertext[block_num]
    
    # if we're on the first block of the ciphertext, its previous block (the one we
    # want to modify to affect changes on the current block), is actually the IV
    prev_block = cipher_iv if block_num == 0 else original_ciphertext[block_num-1]
    
    print( f"\tCurrent block : {pretty_print_bytestring(current_block)}" )
    print( f"\tPrevious block: {pretty_print_bytestring(prev_block)}" )
    
    # placeholder initialization that we will overwrite later. a value of -1 indicates
    # that we have yet to figure out the value for that byte. we will use it later when
    # building the ciphertext/iv to submit to the 'server'
    staging = [-1 for i in range(16)]
    
    # loop BLOCK_SIZE times, because we figure this out a byte at a time for each block
    for pad_value in range( 1, BLOCK_SIZE+1 ):
        print( f"\t-- Working on padding byte: {pad_value}" )
        
        # convenience variable. working on a pad_value of 1 means we're modifying index
        # -1 of staging, pad_value of 2 means we're modifying index -2 of staging, etc.
        # all the way up to a pad_value of 16 modifying index -16 of staging.
        index = -pad_value
        
        # for each value of padding, we are going to brute force values 0x00 - 0xff
        # until we receive a full set of valid padding. for all values of padding past 1,
        # we can use the staging block as reference on how to change the previous block
        # (which is our new iv, effectively, as we are working on two blocks at a time)
        #
        # because remember, the staging bytes will set the resulting plaintext bytes to 0,
        # which means we can just xor that value with our desired padding value to ensure those
        # bytes in the plaintext go to whatever value we want.
        new_iv = bytearray( prev_block )
        
        for i in range( BLOCK_SIZE ):
            if staging[i] != -1:
                new_iv[i] = staging[i] ^ pad_value
        
        # this is where we start brute-forcing
        for byte_val in range(256): # values 0x00 - 0xff  
            new_iv[index] = byte_val
            
            if server.submit_ciphertext( current_block, new_iv ):
                # if we get valid padding back, it means one of two things:
                #   1. we actually did find a byte value that gives us a plaintext
                #       value with valid padding!
                #   2. if on the first padding byte, we found a false positive
                #
                #       let's say that the second-to-last byte of the plaintext
                #       is actually 0x02, for whatever reason. if our byte_val
                #       results in a plaintext value of 0x02, we get valid padding.
                #
                #       easy way to check this is to just flip the second-to-last
                #       byte and see if padding is still valid - if it is, then we
                #       know we're good to go!
                if pad_value == 1:
                    new_iv[-2] ^= 0xaa
                    result = server.submit_ciphertext( current_block, new_iv )
                    new_iv[-2] ^= 0xaa
                    
                    if not result:
                        print( f"\t\t\tMatch rejected: {hex(byte_val)}" )
                        continue
                        
                print( f"\t\t\t* Match found: {hex(byte_val)}" )
                staging[index] = (pad_value ^ new_iv[index])
                print( f"\t\t\t+ Staging block: {pretty_print_bytestring(staging)} " )
            
        if staging[index] == -1:
            print( "[ERROR] No match found. Issue with oracle and/or ciphertext" )
            quit()
                
                
    # decoding it is as simple as XORing our staging block with our previous ciphertext block!
    decoded_block = [staging[i] ^ prev_block[i] for i in range(BLOCK_SIZE)]
    
    # dropping these in cumulative variables for pretty printing later
    cumulative_staging.extend( staging )
    cumulative_decoded[0:0] = decoded_block
    
    print( f"Final staging block for block {block_num}: {pretty_print_bytestring(staging)}" )
    print( f"Previous block XOR Staging block: {bytes(decoded_block)}" )
    print()
    
print( f"Original ciphertext: {pretty_print_bytestring(server.get_original_ciphertext())}" )
print( f"Decoded staging    : {pretty_print_bytestring(cumulative_staging)}" )
print( f"Decoded message    : {bytes(cumulative_decoded)}" )