#!/usr/bin/env python
import hashlib
import sys
import getopt
import base64
import urllib
import binascii
import re


def usage():
    print '''
                           .::::.
                         .::::::::.
                        :::::::::::     """"         """"
                    ..:::::::::::'    ""     "     ""     "
                  '::::::::::::'     ""           ""
                    .::::::::::       ""    """"""""""""""""""""
               '::::::::::::::..        """"         """"
                    ..::::::::::::.
                  ``::::::::::::::::   Coding Conversion Script
                   ::::``:::::::::'        .:::.
                  ::::'   ':::::'       .::::::::.
                .::::'      ::::     .:::::::'::::.
               .:::'       :::::  .:::::::::' ':::::.
              .::'        :::::.:::::::::'      ':::::.
             .::'         ::::::::::::::'         ``::::.
         ...:::           ::::::::::::'              ``::.
        ```` ':.          ':::::::::'                  ::::..
                           '.:::::'                    ':'````..
        '''
    print '[*] This is Coding Conversion script'
    print ''
    print '[*] Total Parameters:'
    print '[*] -h --help             get this script help'
    print
    print '[*] -f                    calculate file hash value, default md5'
    print '[*] --file_md5            use md5 to calculate file hash'
    print '[*] --file_sha1           use sha1 to calculate file hash'
    print '[*] --file_sha256         use sha256 to calculate file hash'
    print '[*] --file_sha512         use sha512 to calculate file hash'
    print
    print '[*] -b --base64_encode    -b option default is base64 encode'
    print '[*] --base64_decode'
    print
    print '[*] -u --url_encode       url encode, -u option default is url encode'
    print '[*] --url_decode'
    print
    print '[*] -e --hex_encode       use hex to encode this string,'
    print '                          -e option default is hex encode'
    print '[*] -e --hex_decode'
    print
    print '[*] -a --ascii_encode     use ascii encode'
    print '[*] -m --md5_hash         use md5 hash algorithm escape string'
    print '[*] --sha1_hash           use sha1 hash algorithm escape string'
    print '[*] --sha256_hash         use sha256 hash algorithm escape string'
    print '[*] --sha512_hash         use sha512 hash algorithm escape string'
    print
    print 'Usage:'
    print '[*] python Coding_Conversion.py -f zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha1 zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha256 zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha512 zip_file.zip'
    print
    print '[*] python Coding_Conversion.py -b "i am your father"'
    print '[*] python Coding_Conversion.py --base64_decode "aSBhbSB5b3VyIGZhdGhlcg=="'
    print
    print '[*] python Coding_Conversion.py -u "select * from users"'
    print '[*] python Coding_Conversion.py -url_decode "%73%65%6c%65%63%74"'
    print
    print '[*] python Coding_Conversion.py -e "i am your father"'
    print '[*] python Coding_Conversion.py --hex_decode "0x6920616d20796f757220666174686572"'
    print '[*] python Coding_Conversion.py -a "nidaye"'
    print '[*] python Coding_Conversion.py -m "nidaye"'
    print '[*] python Coding_Conversion.py --sha1_hash "nidaye"'
    print '[*] python Coding_Conversion.py --sha256_hash "nidaye"'
    print '[*] python Coding_Conversion.py --sha512_hash "nidaye"'
    sys.exit(0)


def main():

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hf:b:u:e:a:m:', [
            'help',
            'file_md5=',
            'file_sha1=',
            'file_sha256=',
            'file_sha512=',
            'base64_encode=',
            'base64_decode=',
            'url_encode=',
            'url_decode=',
            'hex_encode=',
            'hex_decode=',
            'ascii_encode=',
            'md5_hash=',
            'sha1_hash=',
            'sha256_hash=',
            'sha512_hash=',
        ])
    except:
        usage()

    for o, a in opts:
        if o in ['-h', '--help']:
            usage()
        elif o in ['-f', '--file_md5']:
            md5_hash = hashlib.md5(open(a, 'rb').read()).hexdigest()
            print 'File Name:', a
            print 
            print 'Calculate Hash Values: ', md5_hash

        elif o in ['--file_sha1']:
            sha1_hash = hashlib.sha1(open(a, 'rb').read()).hexdigest()
            print 'File Name:', a
            print 
            print 'Calculate Hash Values: ', sha1_hash

        elif o in ['--file_sha256']:
            sha256_hash = hashlib.sha256(open(a, 'rb').read()).hexdigest()
            print 'File Name:', a
            print 
            print 'Calculate Hash Values: ', sha256_hash

        elif o in ['--file_sha512']:
            sha512_hash = hashlib.sha512(open(a, 'rb').read()).hexdigest()
            print 'File Name:', a
            print 
            print 'Calculate Hash Values: ', sha512_hash

        elif o in ['-b', '--base64_encode']:
            base64_str = base64.b64encode(a)
            print 'Raw Data:', a
            print 
            print 'Conversion Data: ', base64_str

        elif o in ['--base64_decode']:
            string = a
            base64_str = base64.b64decode(string)
            print 'Raw Data:', a
            print 
            print 'Conversion Data: ', base64_str

        elif o in ['-u', '--url_encode']:
            str_encode = re.sub(r'.', lambda m: '%%%s' % m.group(0).encode('hex'), a)
            print 'Raw Data:', a
            print 
            print 'Conversion Data: ', str_encode

        elif o in ['--url_decode']:
            str_decode = urllib.unquote(a)
            print 'Raw Data:', a
            print 
            print 'Conversion Data: ', str_decode

        elif o in ['-e', '--hex_encode']:
            hex_code = binascii.hexlify(a)
            print 'Raw Data:', a
            print 
            print 'Conversion Data: 0x%s' % hex_code

        elif o in ['--hex_decode']:
            print 'Raw Data:', a
            print 
            if a[0] == '0' and a[1] == 'x':
                a = a[2:]
            hex_code = binascii.unhexlify(a)
            print 'Conversion Data: ', hex_code

        elif o in ['-a', '--ascii_encode']:
            print 'Raw Data:', a
            print 
            ord_string = ''
            for i in range(len(a)):
                if i == 0:
                    ord_string = str(ord(a[i]))
                else:
                    ord_string = ord_string + ' ' + str(ord(a[i]))
            print ord_string

        elif o in ['-m', '--md5_hash']:
            md5_hash = hashlib.md5(a).hexdigest()
            print 'Raw Data:', a
            print 
            print 'Conversion Data:', md5_hash

        elif o in ['--sha1_hash']:
            sha1_hash = hashlib.sha1(a).hexdigest()
            print 'Raw Data:', a
            print 
            print 'Conversion Data:', sha1_hash

        elif o in ['--sha256_hash']:
            sha256_hash = hashlib.sha256(a).hexdigest()
            print 'Raw Data:', a
            print 
            print 'Conversion Data:', sha256_hash

        elif o in ['--sha512_hash']:
            sha512_hash = hashlib.sha512(a).hexdigest()
            print 'Raw Data:', a
            print 
            print 'Conversion Data:', sha512_hash

        else:
            print 'Can not handle this options'
            print 'Please use -h get help !'
            sys.exit(0)


if __name__ == '__main__':
    main()
