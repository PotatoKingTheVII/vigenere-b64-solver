## Purpose
"If I had a nickel for every time I encountered vigenered base64, I'd have two nickels - which isn't a lot, but it's weird that it happened twice."

And so I made this script for cases where sheer or dictionary bruteforce wouldn't work. When you have base64 ciphertext that has been encrypted with vigenere and that base64 is only carrying printable plaintext (32<=b<=126) this script can give the key used or at least narrow down the search space.

## File usage
**This is not user friendly**. The user inputs are found at the bottom of the file and the basic premise is to run the chunkPossabilities(key_chunk_#, key_length) function in a loop, changing the key_length. If you've enough ciphertext then only one keylength should give any final results. You would then run with that keylength and check the other key chunk numbers one at a time


## High level overview
Since we have the limited case where the base64 must be carrying printable plaintext, we can use that restriction to narrow down possible keys. We can't do a pure bruteforce for all keylengths as 26e5 is already 11 million so we use the handy fact that each 4 character base64 chunk always carries a full 3 bytes of data that we can check. This allows us to bruteforce the key in sections of 4 letters at a time for 26e4.

However, we need to be careful of what base64 chunks we pick to test. A valid chunk to test must only have been affected by the key letters currently under test. For example if we have a 8 length key and we're checking the first 4 letters of the key then we can only pick chunks that have had their letters changed by the key indexes 0,1,2,3. This is made slightly more complicated by the fact that numbers aren't affected by and don't increment the vigenere key.

Take this example with a keylength of 8 and checking the first 4 letters of that key:

|b64|a|H|R|0|c|H|M|6|L|y|9|3|d|3|c|u|e|W|9|1|
|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|
|vig key index|0|1|2|2|3|4|5|5|6|7|7|7|0|0|1|2|3|4|4|4|
|b64 chunk #|1|1|1|1|2|2|2|2|3|3|3|3|4|4|4|4|5|5|5|5|

The b64 chunks 1 and 4 can be tested because they only contain 0, 1, 2

So we build up a list of valid b64 chunks to test, decode the b64 with all possible 26e4 vigenere keys padded with "a" to the keylength under test and then for each key check if it decodes all test chunks to printable plaintext.

Depending on the length of the base64 being tested, there can still be false positives after this first check so a second, less restrictive check, is then performed. Instead of a valid b64 test chunk only containing the key indexes under test we allow any not previously tested chunk that has at least one key index being checked. So for example "3,4,4,5". We then allow all the key indexes that aren't being tested (4, 5 here) to be whatever they want, for a further up to 26e3 combinations. If there isn't at least one valid combination out of these then the key is discarded. This is done for all of these new test chunks and a valid key must have one valid combination for all of them. This can massively reduce any leftover false positives to the point where only one permutation is left.

Additionally we need to do this for all keylengths as even though we pad the unknown vig key letters as "a" so no shift happens for key indexes that aren't being tested, different keylengths will still change the point at which the key resets. Thankfully as we usually only have 1 valid permutation for the correct keylength this also means that wrong keylengths will generally have 0 valid permutations so we can limit possible keylength sizes in this way.

Checking key chunks other than 1 is much the same just with different padding e.g. chunk 2 of a 9 length key is : "aaaaboata". Finally, we only brute the key in chunks of 4 meaning you could have a partial key result bar the last 3 letters but in such as case you're just left with bruteforcing 26e3 possibilities.


## Other base-n systems
Most other base systems can be bruteforced in a similar way with slight changes. For example, base85 works in chunks of 5 for 4 complete bytes while base32 works in chunks of 4 for 2 complete bytes. I'll gradually be adding these separate versions to this repository.

## Dependencies

 - numpy
