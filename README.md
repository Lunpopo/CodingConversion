## Coding_Conversion

##### Coding Conversion script can encode or decode code that like url md5 sha1 sha254 base64 hex
Supporting python2 temporary

### Total Parameters
##### Help Module
-h, --help            show this help message and exit

##### File Hash Module
File Hash Module support comparison Hash provided with file hash calculated and it will return Comparison Result.

eg: python Coding_Conversion.py -f zip_file.zip

-f FILENAME [CUSTOM_HASH], --file-md5 FILENAME [FILENAME ...] -> Calculating file hash value or compare hash of custom provide, default hash algorithm is md5

--file-sha1 FILENAME [CUSTOM_HASH] -> Using sha1 algorithm to calculate file hash or compare custom hash you given to

--file-sha256 FILENAME [CUSTOM_HASH] ->  Using sha256 algorithm to calculate file hash or compare custom hash you given to

--file-sha512 FILENAME [CUSTOM_HASH] -> Using sha512 algorithm to calculate file hash or compare custom hash you given to

##### String Encoding Module
When if the strings of encoding are too long and its contain ' or ", you need to use \ to escape the especially characters.

-b String, --base64-encode String -> -b option default use base64 encoding'

--base64-decode String -> --base64-decode option use base64 to decoding the string you given to

-u String, --url-encode String -> -u or --url-encode option default use url encoding

--url-decode String -> --url-decode option decode the string of url you given to

-e String, --hex-encode String -> -e option use hex to encode this string, -e option default is hex encode algorithm

--hex-decode String -> --hex-decode option use hex decoding module to decode the string you given to

-a String, --ascii-encode -> String ascii encoding

--ascii-decode String -> ascii decoding

-m String, --md5-hash -> String use md5 hash algorithm escape string

--sha1-hash String -> use sha1 hash algorithm escape string

--sha256-hash String -> use sha256 hash algorithm escape string

--sha512-hash String -> use sha512 hash algorithm escape string

### Usage:
```
python Coding_Conversion.py -f zip_file.zip
python Coding_Conversion.py -f zip_file.zip a4048b57c8c9cc53e340fdcbba8066ea
python Coding_Conversion.py --file-sha1 zip_file.zip 
python Coding_Conversion.py --file-sha1 zip_file.zip 39b8a09aae1c6933ae090b6851eb079a731be967 
python Coding_Conversion.py --file-sha256 zip_file.zip
python Coding_Conversion.py --file-sha256 zip_file.zip 488e1bd3268e5d638b0b8154502503ef81f8c253b0c0f4013fab03e1ddbb3913
python Coding_Conversion.py --file-sha512 zip_file.zip
python Coding_Conversion.py --file-sha512 zip_file.zip a28cff98334a590dd173ea0c5b4ae09b4918b1515efcd491150641e59500188df2f46ed7d66e566ecaf2455e7696ed110e0169889b433b9881d016aecfa9ff40

python Coding_Conversion.py -b "i am your father"
python Coding_Conversion.py --base64-decode "aSBhbSB5b3VyIGZhdGhlcg=="

python Coding_Conversion.py -u "select * from users"
python Coding_Conversion.py -url-decode "%73%65%6c%65%63%74%20%2a%20%66%72%6f%6d%20%75%73%65%72%73"

python Coding_Conversion.py -e "i am your father"
python Coding_Conversion.py --hex_decode "6920616d20796f757220666174686572"

python Coding_Conversion.py -a "nidaye"
python Coding_Conversion.py --ascii-decode "110 105 100 97 121 101"

python Coding_Conversion.py -m "nidaye"'
python Coding_Conversion.py --sha1_hash "nidaye"'
python Coding_Conversion.py --sha256_hash "nidaye"'
python Coding_Conversion.py --sha512_hash "nidaye"'
```

### Author
Lunpopo

source link: [Github](https://github.com/Lunpopo/Coding_Conversion)

This is a simple and small tool and wellcome to feedback. 

If you have any question or awesome suggestion please contact me, Thanks a lot! [commit issues](https://github.com/Lunpopo/Coding_Conversion/issues)
