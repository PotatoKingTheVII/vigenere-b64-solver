from multiprocessing import Pool
import base64 as b64
import numpy as np
import itertools
import math


#Split a list up into chunkNum number of lists, seems to use less memory than np.split
def splitChunks(arrayIn, chunkNum):
    fullArray = []
    chunkNum = (len(arrayIn)//threads)
    chunkSize = len(arrayIn)//chunkNum

    for i in range(0,chunkNum-1):
        start = i*chunkSize
        fullArray.append(arrayIn[start:start+chunkSize])

    fullArray.append(arrayIn[(chunkNum-1)*chunkSize::])
    return fullArray

#Optimized vigenere decode function
def vigDecode(ciphertext, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    alphabetU = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    alph_dict = {"a":0, "b":1, "c":2, "d":3, "e":4, "f":5, "g":6, "h":7, "i":8, "j":9, "k":10,
                 "l":11, "m":12, "n":13, "o":14, "p":15, "q":16, "r":17, "s":18, "t":19, "u":20,
                 "v":21, "w":22, "x":23, "y":24, "z":25}
    
    alph_dict_U = {"A":0, "B":1, "C":2, "D":3, "E":4, "F":5, "G":6, "H":7, "I":8, "J":9, "K":10,
                 "L":11, "M":12, "N":13, "O":14, "P":15, "Q":16, "R":17, "S":18, "T":19, "U":20,
                 "V":21, "W":22, "X":23, "Y":24, "Z":25}

    #Convert the key to numerical shifts:
    keyShifts = []
    for i, letter in enumerate(key):
        keyShifts.append(alphabet.find(letter))
    key_length = len(key)


    #Do the actual decryption:
    plaintext = ""
    shiftCount = 0

    for i in range(0, len(ciphertext)):
        shift = 0
        letter = ciphertext[i]
        if(letter.islower()):
            plaintext+=alphabet[(alph_dict[letter] - keyShifts[shiftCount%key_length]) % 26]
            shiftCount+=1
        elif(letter.isupper()):
            plaintext+= alphabetU[( alph_dict_U[letter] - keyShifts[shiftCount%key_length]) % 26]
            shiftCount+=1
        else:
            plaintext+=letter
            
    return plaintext

#For use with multiprocess, calculate vig plaintext for the entire given list
def vigenereDecodeList(keyList):
    vigenereSubArray = []
    for key in keyList:
        tmp_ct = vigDecode(ciphertext, key)
        vigenereSubArray.append([tmp_ct, key])
    return vigenereSubArray

#Check if the input bytes are all valid i.e. in the normal and printable range
#Try sections to accommodate any last padded chunks which carry fewer bytes
def validate(current_bytes):
    valid = 0
    b1 = current_bytes[0]
    try:
        b2 = current_bytes[1]
    except:
        b2 = 50

    try:
        b3 = current_bytes[2]
    except:
        b3 = 50
    
    if(32 <= b1 <= 126 and 32 <= b2 <= 126 and 32 <= b3 <= 126):
        valid = 1

    return valid

#Check if a group string has only the numbers we're interested in for whatever chunk we're looking at i.e. 0123 for chunk 1
def validGroup(group_in, non_valid_numbers):
    for number in non_valid_numbers:
        if(number in group_in):
            return False
    return True

#Check if a group has at least one known value (Can change to if there's at least 2 known values to speed up the last check
#At the cost of more false positives)
def validGroupFinal(group_in, valid_numbers):
    for number in valid_numbers:
        if number in group_in:
            return True
 
    return False
#(Might also be some edge cases where we need to check that the known value doesn't land on a number
#Or the dof values are all numbers in the future)





vig_alph = "abcdefghijklmnopqrstuvwxyz"
#Main function, find the valid keys for the given chunk and key-length under test
def chunkPossabilities(chunk, key_length):
    ##########################Make 4-long key permutations##########################
    ##
    four_long_permutation_list_tmp = ([p for p in itertools.product(vig_alph, repeat=4)])
    four_long_permutation_list = []
    for perm in four_long_permutation_list_tmp:
        four_long_permutation_list.append("".join(perm).rjust((chunk)*4, "a").ljust(key_length, "a"))
    print("Starting first check with only fully known chunks...\r\n")




    ##########################For each key work out the decoded vigenere ciphertext##########################
    ##

    #Calculate a list of the vig keys with their decoded ciphertexts:
    vigged_cts = []

    #We split the list of combinations up into chunks for the number of processes we're using
    sub_key_lists = splitChunks(four_long_permutation_list, threads)

    #Calculate vig plaintexts with multithreadings
    print("Calculating decoded vigenere plaintexts...")
    with Pool(threads) as p:
        results = (p.map(vigenereDecodeList, sub_key_lists))

    #Combine each thread's sublist results once they're finished
    vigged_cts = [item for sublist in results for item in sublist]

    ###Check for valid groups e.g. for example in the 1 chunk case:
    ###We now check for keys which only contain the first 4 vig letters but can start with a key index other than 0, as long as it still only has 0 to 3 key index i.e. 1123
    ###This is a more generic form of checking where the key_index % length == 0 and the ct_index % 4 = 0

    ##########################Create a list to tell us what chunks we can check are valid or not i.e. only vigged by the first 4 letters of the key##########################
    ##

    print("Checking plaintexts for valid keys...")
    #Now make a string of the key indexes in the format: 012344450001222345 (Repeated means number) so we can check for any suitable cases to check the permutations against
    #We always start on the first index of the key
    key_history = [0]

    #Keep track of where we are in the key and ciphertext
    ct_index = 0
    key_index = 0

    #Start edge case:
    while not ciphertext[ct_index].isalpha():
        key_history.append(0)
        ct_index+=1
    ct_index+=1

    #For the whole ct
    while ct_index < len(ciphertext):

        #Only increment the vig key if it's a letter CT we're on
        if(ciphertext[ct_index].isalpha()):    #Numbers won't increment vig key
            key_index += 1

        ct_index +=1
        key_history.append(key_index%key_length)

    #Now we can split this up into groups of 4 and check which groups only contain relevant key indexes (0-3 in 1 chunk case)
    groups = [key_history[i:i+4] for i in range(0, len(key_history), 4)]

    #Check what nubmers aren't valid for this chunk
    #(Done once outside of function to avoid repeated calculations of it)
    non_valid_numbers = list(range(0, key_length))
    for i in range((chunk-1)*4, ((chunk-1)*4)+4):
        non_valid_numbers.remove(i)    

    #Actually check each group to see which ones are alright to test later
    text_indicies = []
    for i, index_group in enumerate(groups):
        if(validGroup(index_group, non_valid_numbers)):
            text_indicies.append(i*4)

    if(len(text_indicies) == 0):
        print("Warning no valid groups to check")

    ##########################Check the actual groups we found above with every key to see which ones are valid##########################
    ##
            
    #So for each decoded ciphertext with the keys we look at the i*4:(i*4)+4 indexes (i.e. full 4 length boundary chunks) and check which ones are valid
    #For each of the keys do:
    second_remaining = []
    for remaining_permutation in vigged_cts:
        valid = True
        decoded_ct = remaining_permutation[0]

        #Check if all of the additional idicies from above are valid
        for current_index in text_indicies:
            current_chunk = decoded_ct[current_index:current_index+4]
            decoded_chunk = b64.b64decode(current_chunk)
            if(not validate(decoded_chunk)):    #If it isn't valid then don't bother checking the rest
                valid = False
                break
        if(valid):
            second_remaining.append(remaining_permutation[1])

    print("\r\nRemaining keys after the first check: " , len(second_remaining))
    print("Starting final check...\r\n")




##############################Final check start, decode the CT with the remaining keys#######################################
    

    ##We now check the final case, chunks with at least one or more of the key index but also with key indexes more than 3 i.e. 2345
    ##Where we assume the keys more than 3 can be whatever and we're only constrained by the known remaining list for the known 0-3 parts
    ##If any of the remaining keys don't work when you allow the unknown parts to be anything then remove them:

    #Prepare the remaining keys and get their decoded cts
    count = 0
    vigged_cts = []
    for key in second_remaining:
        percentage = ((count/len(four_long_permutation_list))*100)
        if(count%math.floor(len(four_long_permutation_list)/5) == 0 ):
            pass
        tmp_ciphertext = vigDecode(ciphertext, key)
        vigged_cts.append([tmp_ciphertext,key])
        count+=1

    valid_numbers = []
    for i in range((chunk-1)*4, ((chunk-1)*4)+4):
        valid_numbers.append(i)


    #Get the appropirate groups of indexes to test with at least 1 known
    text_indicies_final = []
    for i, index_group in enumerate(groups):
        if(validGroupFinal(index_group, valid_numbers)):
            if(i*4 not in text_indicies):
                text_indicies_final.append([i*4, index_group])

    if(len(text_indicies_final) == 0):
        print("Warning no valid groups to check")


    ##Begin actually checking all of these groups for each remaining key
    #For each key permutation left:
    final_chunk_1_list = []
    count = 0
    for last_permutations in vigged_cts:
        count+=1
        
        percentage = ((count/len(vigged_cts))*100)
        if(count%math.ceil(len(vigged_cts)/5) == 0 ):
            print(str(math.ceil(percentage))+"%")

        #For any of the remaining keys to be valid with the rest of the groups with x degrees of freedom then at least one of the free
        #permutations must be valid for all of the groups, if any of those groups don't have a valid permutation then the key isn't valid
        decoded_ct = last_permutations[0]
        
        overall_valid = True    #Keeps track of if all of the groups have passed or not
        for group_perm in text_indicies_final:
            group_valid = False #Keeps track of this specific permutation of the current group has passed or not
            
            #Then one of the group_valid checks has returned false after trying all permutations for it and set it overall to False
            if(not overall_valid):
                break   #One of the groups has failed so the key as a whole has failed, don't bother going on

            #Get what we're currently checking
            current_index = group_perm[0]
            current_chunk = decoded_ct[current_index:current_index+4]
    ##        if(current_chunk.find("=")!=-1):    #Quick hack to skip the last chunk
    ##            continue                        #These cases should work now but I don't trust myself enough to remove this


            #Make a list of a constructor that will tell us how to re-make the string with all possible permutations in the form:
            #0 = Just copy the decoded_ct over, it's either a number or one of our known key values we're checking atm from last_permutations
            #1 = A true unknown that can have whatever permutation it wants (Lowercase)
            #2 = A true unknown that can have whatever permutation it wants (Uppercase)
            construction_tree = []
            for i in range(0,4):
                tmp_ltr = group_perm[1][i]  #Current letter of CT we're on
                
                if(not current_chunk[i].isalpha()):   #Is it a number or +/=? i.e. not affected by vig
                    construction_tree.append(0)
                elif(tmp_ltr == valid_numbers[0] or tmp_ltr == valid_numbers[1] or tmp_ltr == valid_numbers[2] or tmp_ltr == valid_numbers[3] ):    #If it's one of the known keys
                    construction_tree.append(0)
                elif(current_chunk[i].islower()):
                    construction_tree.append(1)
                elif(current_chunk[i].isupper()):
                    construction_tree.append(2)
                else:
                    print("Error in construction tree, non-valid input")
                    print("The error char is", tmp_ltr, current_chunk[i], current_chunk)


            #Count the degrees of freedom i.e. number of 1s or 2s
            dof = construction_tree.count(1) + construction_tree.count(2)

            #Make all permutations for the unknown d.o.f:
            alph = "abcdefghijklmnopqrstuvwxyz"
            leftover_permutations = list(itertools.product(alph, repeat=dof))

            #Check for the very rare case where it's just one known and the rest are numbers just let these pass
            if(len(leftover_permutations)==0):
                group_valid = True
                continue
            
            #Now go through all permutations and construct the strings and test them
            #At least one permutation needs to pass 
            for unknown_perm in leftover_permutations:

                #Make the chunk with the a-z permutations from above following the construction tree we made earlier
                unknown_index = 0
                constructed_chunk = ""
                for i in range(0, 4):
                    try:
                        instruction = construction_tree[i]
                    except:
                        print(construction_tree)
                    if(instruction == 0):    #Then just copy the number or our known CT
                        constructed_chunk += current_chunk[i]
                    elif(instruction == 1):
                        constructed_chunk += unknown_perm[unknown_index]
                        unknown_index+=1
                    elif(instruction == 2):
                        constructed_chunk += unknown_perm[unknown_index].upper()
                        unknown_index+=1                        
      
                #Now we test this constructed chunk
                if(validate(b64.b64decode(constructed_chunk))):
                    group_valid = True
                    break   #If this permutation is valid skip the other permutations and set this particular group to valid

            #If we've checked all permutations for this group and none are valid then the key itself can't be valid full stop, skip checking the other groups
            if(not group_valid):
                overall_valid = False

        #This means that for all the dof groups at least one of the permutations were valid so the key is valid and we add it here
        if(overall_valid):
            final_chunk_1_list.append(last_permutations[1])

    print("\r\nRemaining keys after the last check: ", (final_chunk_1_list))


    return True


#############USER INPUT###################
ciphertext = """M291jZKsT3UeVue0BFBsyTUzSlFwzDsztU50lcZ0wONzSuZZNM1YBEF4CU1sjZNenKDejZNem28kyTYguEgka3NpxLZyDVFtHbZyhFNevsmfP3b3zg55u3O0bGNjHuGozC93CVNrtW92NGVPzhK3HTnrUCVK"""
threads = 6 #Set to about 2/3 of your actual threads

#Only run if main process, not multithread child:
if __name__ == '__main__':
    chunkPossabilities(1, 8)



