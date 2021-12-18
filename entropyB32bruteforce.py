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
        tmp_ct = b64.b32decode(tmp_ct)
        vigenereSubArray.append([tmp_ct, key])
    return vigenereSubArray

####For use with multiprocess, calculates entropy of given list of data
def CalculateEntropyList(dataList):
    entropySubArray = []
    for data in dataList:
        result = data[0]
        entropyCalc = ShannonEntropy(result, range_bytes)
        temp = [entropyCalc, result,data[1]]
        entropySubArray.append(temp)
    return entropySubArray



####Entropy function
def range_bytes(): return range(256)
def ShannonEntropy(data, iterator=range_bytes):
    if not data:
        return 0
    entropy = 0
    for x in iterator():
        p_x = float(data.count(int(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

vig_alph = "abcdefghijklmnopqrstuvwxyz"



###USER INPUTS###
ciphertext = """EnterCiphertextHere"""
threads = 6


###Only run this section if not a child process
if __name__ == '__main__':
    #For each brute key length
    for brute_len_i in range(2,20):
        #For each actual key length
        for key_len_j in range(2,20):
            #The actual key can't be smaller than the brute key
            if(key_len_j < brute_len_i):
                continue
            
            print(brute_len_i, key_len_j)
            permutation_list_tmp = ([p for p in itertools.product(vig_alph, repeat=brute_len_i)])
            permutation_list = []
            for perm in permutation_list_tmp:
                permutation_list.append("".join(perm).ljust(key_len_j, "a"))

            #Calculate the vigged cts
            vigged_cts = []

            #We split the list of combinations up into chunks for the number of processes we're using
            sub_key_lists = splitChunks(permutation_list, threads)

            #Calculate vig plaintexts with multithreadings
            print("Calculating decoded vigenere plaintexts...")
            with Pool(threads) as p:
                results = (p.map(vigenereDecodeList, sub_key_lists))

            #Combine each thread's sublist results once they're finished
            vigged_cts = [item for sublist in results for item in sublist]

            #Split results up again to calculate entropy with multiple threads
            comboChunks = splitChunks(vigged_cts,threads)
            #print("this", comboChunks[0][0][0])
            with Pool(threads) as p:
                results = (p.map(CalculateEntropyList, comboChunks))

            #Combine each thread's sublist results once they're finished
            entropyArray = [item for sublist in results for item in sublist]
            entropyArray = sorted(entropyArray) #Sort so smallest is first, most likely to be valid

            #Write results to file in order of entropy
            with open("output brute "+str(brute_len_i) + " len " + str(key_len_j) + ".txt", "wb") as fout:
                for i in range(0,len(entropyArray)):
                    entropyFormat = ((str(entropyArray[i][0])).ljust(4,"0"))[0:4]
                    passFormat = entropyArray[i][2]
                    fout.write(entropyFormat.encode("ascii"))
                    fout.write(b"   ")
                    fout.write(passFormat.encode("ascii"))
                    fout.write(b"   ")
                    fout.write(entropyArray[i][1])
                    fout.write(b"\n")
            print("Dumped to file")

