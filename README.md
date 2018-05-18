## Coding_Conversion

##### Coding Conversion script, can conversion coding or decode like url md5 sha1 sha254 base64 hex

### Total Parameters:
```
-h --help               get this script help
-f                      calculate file hash value, default md5
--file_md5              use md5 to calculate file hash
--file_sha1             use sha1 to calculate file hash
--file_sha254           use sha254 to calculate file hash

-b --base64_encode      -b option default is base64 encode
--base64_decode

-u --url_encode         url encode, -u option default is url encode'
--url_decode'

-e --hex_encode         use hex to encode this string,'
                        -e option default is hex encode'
-e --hex_decode'
```

### Usage:
```
python Coding_Conversion.py -f zip_file.zip'
python Coding_Conversion.py --file_sha1 zip_file.zip'
python Coding_Conversion.py --file_sha254 zip_file.zip'
    
python Coding_Conversion.py -b "i am your father"'
python Coding_Conversion.py --base64_decode "aSBhbSB5b3VyIGZhdGhlcg=="'
  
python Coding_Conversion.py -u "select * from users"'
python Coding_Conversion.py -url_decode "select%20%2A%20from%20users"'
  
python Coding_Conversion.py -e "i am your father"'
python Coding_Conversion.py --hex_decode "6920616d20796f757220666174686572"'
```
