#!/usr/bin/python3
import binascii
from calendar import c
from BitVector import *

# First table entry for permutating the original key called PC-1
# This will create a 56 bit permutation of key (8 x 7)
PC_1 = [56, 48, 40, 32, 24, 16, 8,
            0, 57, 49, 41, 33, 25, 17,
            9, 1, 58, 50, 42, 34, 26,
            18, 10, 2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14,
            6, 61, 53, 45, 37, 29, 21,
            13, 5, 60, 52, 44, 36, 28,
            20, 12, 4, 27, 19, 11, 3]
    
# Second table entry for permutating the 56-bit key called PC-2
# This creates a 48 bit permutation of the key (8 x 6)
PC_2 = [13, 16, 10, 23, 0, 4,
            2, 27, 14, 5, 20, 9,
            22, 18, 11, 3, 25, 7,
            15, 6, 26, 19, 12, 1,
            40, 51, 30, 36, 46, 54,
            29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52,
            45, 41, 49, 35, 28, 31 ]

# Table for Initial Permutation IP of the 64 bit message data
IP = [57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7,
          56, 48, 40, 32, 24, 16, 8, 0,
          58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6]
    
# Table for the E Bit-Selection to take 32 bits and permute them into 48 bits
E = [31, 0, 1, 2, 3, 4,
         3, 4, 5, 6, 7, 8,
         7, 8, 9, 10, 11, 12,
         11, 12, 13, 14, 15, 16,
         15, 16, 17, 18, 19, 20,
         19, 20, 21, 22, 23, 24,
         23, 24, 25, 26, 27, 28,
         27, 28, 29, 30, 31, 0]
    
# Tables defining the function for our Sboxes s1 - s8
sBox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
    
# Table for the permutation  that yields a 32-bit ouput from a 32-bit input block 
P = [15, 6, 19, 20,
         28, 11, 27, 16,
         0, 14, 22, 25,
         4, 17, 30, 9,
         1, 7, 23, 13,
         31, 26, 2, 8,
         18, 12, 29, 5,
         21, 10, 3, 24 ]

# Table for the permuatation
inverseIP = [39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25,
                32, 0, 40, 8, 48, 16, 56, 24 ]

def asciiToHex(asciiData):
    # Convert from ascii to hex
    asciiData = binascii.hexlify(asciiData.encode('utf-8'))
    asciiData = asciiData.decode('utf-8')
    
    return asciiData

def roundKeyGeneration(key):
    
    # Create a BitVector of the original Key (remember this key is in hex form)
    keyIn64Bit = BitVector(hexstring = key)
    
    # permute the 64Bit original key and put it in keyIn56Bit
    keyIn56Bit = keyIn64Bit.permute(PC_1)
    
    # Create a list subKeys to hold our 16 keys that we are to generate
    # i will be our counter for the Round
    subKeys = []
    i = 1
    
    # Now we divide our 56-bit key into two halves L and R (These will both be 28-bits)
    [L,R] = keyIn56Bit.divide_into_two()
    
    # Begin subKey Generation which will generate a total of 16 keys
    while(i < 17):
        
        # Following the chart, only on iterations 1, 2, 9, and 16 do we circular shift once
        # Otherwise we do a circular shift twice
        if i == 1 or i == 2 or i == 9 or i == 16:
            L << 1
            R << 1
        else:
            L << 2
            R << 2
        
        # After we shift L and R properly we concatenate the pairs and perform a permutate from PC-2
        # Permutating the newly shifted 56 bit key with PC-2 creates the key in 48-bit form
        keyIn56Bit = L + R

        keyIn48Bit = keyIn56Bit.permute(PC_2)
        
        # Now that we have the permutated 48 bit key, we put it inside our array subKeys
        subKeys.append(keyIn48Bit)
        
        # Increase our Loop counter
        i = i + 1
        
    # END WHILE
    
    # Return our list of subKeys
    return subKeys

def encryption(originalMessage, subKeys):
    
    """ This function implements the DES encryption function
    
    Args:
        originalMessage (string): Message that the user would like to encrypt
        subKeys (list): List of 16 subKeys that were computed by roundKeyGeneration() function

    Returns:
        encryption (string): The encrypted message in hexadecimal
    """
    
    # Convert our original message into a Bit Vector
    message = BitVector(hexstring = originalMessage)
    
    # Perform the initial permutation for 64 bit message data and store in message
    message = message.permute(IP)
    
    # Now we want to divide the 64-bit message data in half (L0, R0) first iteration so we start at 0
    [l0, r0] = message.divide_into_two()
    
    # Go through 16 iterations, using function f(R n-1, K n) XOR with L n-1 = Rn
    # Start with round counter i = 0
    i = 0
    
    while(i < 16):
        # Calculate the f function
        
        # Set L1 equal to R0 (Remember R0 is the right half of the permutated message)
        l1 = r0
        
        # Permute R0 with the E-bit selection table and set it equal to Rn (This expands to 48 bits instead of 32 bits)
        rn = r0.permute(E)
        
        # The next step to computing the f function is to XOR the output of the permuted bits with the subKey for that round ( ^ is XOR in Bit Vector)
        
        # ISSUE rn is not the same
        rn = rn ^ subKeys[i]
        
        # We have not yet finished function f yet, but now with the 48 bits, we must run them through S-boxes now.
        # This will be our S-box loop counter and our bitNumber counter to iterate through bits
        s = 0
        bitNumber = 0
        
        # Create variable result for the output this must be type string
        result = ''
        
        # Iterate through each s box (There are 8)
        while(s < 8):
            # j will be our counter for processing the individual bits sCalculation is for computing the 4 bits result from 6 bits
            j = 0
            
            # We will create a list and put 6 bits for each elment in list sBits[0] = 0, 1, 1, 0, 0, 0
            sBits = []
            
            # Run a loop to put 6 bits into each element in sBits
            while( j < 6):
                # Append each 6 bits to the list convert to str
                sBits.append(str(rn[bitNumber]))
                bitNumber = bitNumber + 1
                j = j + 1
            
            # Determine the values for row, and column to send to the key in order to compute the 4 bits
            # row is equal to the 0 bit + the last bit of the 6 bit number 
            # column is equal to the bit 1 - 4
            row = int((sBits[0] + sBits[-1]), 2)
            column = int(''.join(sBits[1:5]), 2)
            
            # Now that we have the row and column index in order to retrieve the data from the sBox
            # Remeber the sBox is our list in that we are holding each table for s1 - s8
            # Send j to determine which s box in the list we are referring to, use row to determine the row for specific box, use column to determine column
            # Convert it to hexadecimal
            sBits = hex(sBox[s][row][column])
            
            # Start at 2nd element to get rid of the 0x format
            result = result + sBits[2:]
            
            s = s + 1
        # END S-BOX Process
        
        # Last step for the f function is to do a permutation of P of the S-box output to obtain final value of f
        # Update Rn to be a BitVector of the sbox result
        rn = BitVector(hexstring = result)
        
        # Compute final step for function f
        result = rn.permute(P)
        
        result = result ^ l0
        r1 = result
        l0 = l1
        r0 = r1
        i = i + 1
    
    # After all 16 rounds are finished we reverse the order of the 2 blocks into the 64-bit block and apply final permutation
    # IP ^ -1
    # Swap Left and Right
    result = r1 + l1
    
    # Perform last permutation
    result = result.permute(inverseIP)
    encryption = result.get_hex_string_from_bitvector()
    
    
    return encryption


def decryption(encryptedMessage, subKeys):
    """ Function computes the encryptedMessage with subkeys but in reverse
        It essentially does the exact same thing as encryption just with reverse subKeys

    Args:
        encryptedMessage (string): This is the encrypted data that was returned by encryption() function
        subKeys (list): These are the 16 subKeys that was computed by the roundKeyGeneration() function
    """
    
    
    # Convert our original message into a Bit Vector
    message = BitVector(hexstring = encryptedMessage)
    
    # Reverse the keys for decryption
    subKeys.reverse()
    
    # Perform the initial permutation for 64 bit message data and store in message
    message = message.permute(IP)
    
    # Now we want to divide the 64-bit message data in half (L0, R0) first iteration so we start at 0
    [l0, r0] = message.divide_into_two()
    
    
    # Go through 16 iterations, using function f(R n-1, K n) XOR with L n-1 = Rn
    # Start with round counter i = 0
    i = 0
    
    while(i < 16):
        # Calculate the f function
        
        # Set L1 equal to R0 (Remember R0 is the right half of the permutated message)
        l1 = r0
        
        # Permute R0 with the E-bit selection table and set it equal to Rn (This expands to 48 bits instead of 32 bits)
        rn = r0.permute(E)
        
        # The next step to computing the f function is to XOR the output of the permuted bits with the subKey for that round ( ^ is XOR in Bit Vector)
        
        # ISSUE rn is not the same
        rn = rn ^ subKeys[i]
        
        # We have not yet finished function f yet, but now with the 48 bits, we must run them through S-boxes.
        # The net result of the S-box operations is that the 8 groups of 6 b its that we got from permutating(E), are
        # going to be transformed into 8 groups of 4 bits for a total of 32 bits total.
        
        # This will be our S-box loop counter and our bitNumber counter to iterate through bits
        s = 0
        bitNumber = 0
        
        # Create variable result for the output this must be type string
        result = ''
        
        # Iterate through each s box (There are 8)
        while(s < 8):
            # j will be our counter for processing the individual bits sCalculation is for computing the 4 bits result from 6 bits
            j = 0
            
            # We will create a list and put 6 bits for each elment in list sBits[0] = 0, 1, 1, 0, 0, 0
            sBits = []
            
            # Run a loop to put 6 bits into each element in sBits
            while( j < 6):
                # Append each 6 bits to the list convert to str
                sBits.append(str(rn[bitNumber]))
                bitNumber = bitNumber + 1
                j = j + 1
            
            # Determine the values for row, and column to send to the key in order to compute the 4 bits
            # row is equal to the 0 bit + the last bit of the 6 bit number 
            # column is equal to the bit 1 - 4
            row = int((sBits[0] + sBits[-1]), 2)
            column = int(''.join(sBits[1:5]), 2)
            
            # Now that we have the row and column index in order to retrieve the data from the sBox
            # Remeber the sBox is our list in that we are holding each table for s1 - s8
            # Send j to determine which s box in the list we are referring to, use row to determine the row for specific box, use column to determine column
            # Convert it to hexadecimal
            sBits = hex(sBox[s][row][column])
            
            # Start at 2nd element to get rid of the 0x format
            result = result + sBits[2:]
            
            s = s + 1
        # END S-BOX Process
        
        # Last step for the f function is to do a permutation of P of the S-box output to obtain final value of f
        # Update Rn to be a BitVector of the sbox result
        rn = BitVector(hexstring = result)
        
        # Compute final step for function f
        result = rn.permute(P)
        
        result = result ^ l0
        r1 = result
        l0 = l1
        r0 = r1
        i = i + 1
    
    # After all 16 rounds are finished we reverse the order of the 2 blocks into the 64-bit block and apply final permutation
    # IP ^ -1
    # Swap Left and Right
    result = r1 + l1
    
    # Perform last permutation
    result = result.permute(inverseIP)
    
    # This is the decrypted value from the function
    decryption = str(result)
    decryption = result.get_hex_string_from_bitvector()
    
    # Unpad the message if it was padded
    unpadded_decryption = ""
    unpadded_decryption = unpadMessage(decryption)
    
    # Make sure to reverse subKeys back to normal before ending function
    # IF you dont then next time you enter the function it will reverse it back to normal
    subKeys.reverse()
    
    # Finally return the decryption text
    return unpadded_decryption

def unpadMessage(encryption):
    
    unpadded_encryption = ""
    reversed_encryption = ""
    
    if(encryption[len(encryption) - 1] == '0'):
        # Reverse the string
        for i in reversed(encryption):
            reversed_encryption = reversed_encryption + i
            
        # Iterate over the string and find the index where the first non zero value is
        for i in range(len(reversed_encryption)):
        
            # This if statement checks the element its at, and the next element if they both have '0' value.
            # If so then increment i by 2 so that we can check the next two values.
            # Do this until we find that there are not two zeros in both slots and break
            if(i != len(reversed_encryption) and reversed_encryption[i] == '0' and reversed_encryption[i + 1] == '0'):
                i = i + 2
            else:
                if( i % 2 == 0):
                    delete_index = i
                else:
                    i = i + 1
                    delete_index = i
                    
                delete_index = i
                break
                
        # Slice the string from the first non-zero index until the end of string
        reversed_encryption = reversed_encryption[delete_index:]
    
        # Now reverse the string again which makes gives us the decrypted unpadded hex value
        for i in reversed(reversed_encryption):
            unpadded_encryption = unpadded_encryption + i
    
        unpadded_encryption = BitVector(hexstring = unpadded_encryption)

        unpadded_encryption = unpadded_encryption.get_bitvector_in_ascii()
    else:
        unpadded_encryption = BitVector(hexstring = encryption)
        unpadded_encryption = unpadded_encryption.get_bitvector_in_ascii()
    
    return unpadded_encryption

def padMessage(message):
    
     # Convert message to a BitVector for padding if needed
    message = BitVector(hexstring = message)
    # These will be our starting indexes needed for splicing the message
    start = 0
    end = 64
    
    # We will hold our messages in this list
    hex_message_blocks = []
    
    # Holds the total number of bits in the message
    total_length = message.length()
    
    # Iterations is how many messages we will have based on how many bits there are in total / 64
    # IF there are 200 bits then there will be 4 message blocks, 3 - 64 bits, and 1 that needs to be padded to 64
    iterations = 0
    iterations = int((total_length / 64) + 1)
    
    # The loop will execute 4 times since we have 4 message blocks total
    while(iterations > 0):
     
        # IF the number of bits is above 64 then append the first 64 bits into hex_message_blocks for our first block
        if(total_length > 64):
            
            # start and end were defined in the beginning then recalculated at the end of this block
            # Put the first 64 bits into temp
            temp = message[start:end]
            
            # Append the first 64 bits to hex_message_blocks for our first message
            hex_message_blocks.append(temp.get_bitvector_in_hex())
            
            # Recalculate our total_length and indices
            total_length = total_length - 64
            temp = start + 64
            start = end
            end = temp + 64
        
        # If the total_length of the message block is below 64 then pad with zeros
        elif(total_length < 64):
            
            # Readjust the indices start and end
            # Start must be 
            # 64 bits behind end while End is equal to message.length()
            start = end - 64
            end = message.length()
            
            # Put the 64 bits into temp
            temp = message[start:end]
                
            # Calculate how many bits we need to pad to the end
            n = 64 - total_length
            temp.pad_from_right(n)
            
            # Append it to hex_message_blocks
            hex_message_blocks.append(temp.get_bitvector_in_hex())
            
            # Readjust total_length
            total_length = total_length - 64
        
        # IF the total_length is 64 then we dont need any padding
        elif(total_length == 64):
            
            iterations = iterations - 1
            
            # Put the 64 bits into temp
            temp = message[start:end]
            
            # Append temp to hex_message_blocks
            hex_message_blocks.append(temp.get_bitvector_in_hex())
            
            # Readjust start and end
            start = end
            end = message.length()
            
        iterations = iterations - 1
    
    # At this point the entire message should be parsed into hex_message_blocks
    # Each entry should have 64 bits
    return hex_message_blocks

def getUserMessage():
    
    message = input("Enter a message in ascii to encode: ")
    message = asciiToHex(message)
    
    return message

def getUserKey():
    error = 1
    while(error == 1):
        # Get input from user
         key = input("Enter 8 characters in ascii for the key: ")
         
         # Check if input has an error
         if len(key) != 8:
             print("The key needs to be exactly 8 characters in ascii. Please enter again ")
         else:
             error = 0
    
    key = asciiToHex(key)
    
    return key
            

def main():
    
    # Prompt the user for the message
    message = getUserMessage()
    hex_message_padded_blocks = padMessage(message)
    
    # Prompt the user for the key
    key = getUserKey()
    
    # This function will take the original key and return back a list of 16 subKeys
    subKeys = roundKeyGeneration(key)
    
    # This function takes the message and subKeys that was calculated by roundKeyGeneration and outputs the encrypted_message
    encrypted_message = ""
    entire_encrypted_message = ""
    entire_decryption_message = ""
    decrypted_message = ""
    hex_encryption_blocks = []
    
    # This loop iterates over the padded message blocks, encrypts each one that puts it into hex_encryption_blocks
    for i in hex_message_padded_blocks:
        encrypted_message = encryption(i, subKeys)
        entire_encrypted_message = entire_encrypted_message + encrypted_message
        hex_encryption_blocks.append(encrypted_message)
    
    
    # This loop iterates over the hex_encryption_blocks that were determined in the above loop and returns a decrypted message
    for i in hex_encryption_blocks:
        decrypted_message = decryption(i, subKeys)
        entire_decryption_message = entire_decryption_message + decrypted_message
    
    # Print the encrypted message and the decrypted message to the screen
    print()
    print("Encrypted Message: ", entire_encrypted_message)
    print("Decrypted Message: ", entire_decryption_message)
    print()
        
    


# Tells python script to begin here
if __name__ == '__main__':
    main()