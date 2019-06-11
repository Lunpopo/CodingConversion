#!/usr/bin/env python
# encoding: utf8
import hashlib
import sys
import getopt
import base64
import urllib
import binascii
import re
from termcolor import colored
"""
Available text colors:
red, green, yellow, blue, magenta, cyan, white.
"""


def banner():
    print '''\033[0;31;36m
 _____           _ _             _____                               _             
/  __ \         | (_)           /  __ \                             (_)            
| /  \/ ___   __| |_ _ __   __ _| /  \/ ___  _ ____   _____ _ __ ___ _  ___  _ __  
| |    / _ \ / _` | | '_ \ / _` | |    / _ \| '_ \ \ / / _ \ '__/ __| |/ _ \| '_ \ 
| \__/\ (_) | (_| | | | | | (_| | \__/\ (_) | | | \ V /  __/ |  \__ \ | (_) | | | |
 \____/\___/ \__,_|_|_| |_|\__, |\____/\___/|_| |_|\_/ \___|_|  |___/_|\___/|_| |_|
                            __/ |                                                  
                           |___/                                                   

                           """"         """"
                         ""     "     ""     "
                        ""           ""
                         ""    """"""""""""""""""""
                           """"         """"

                         Coding Conversion Script
    \033[0m'''


def usage():
    banner()

    print '[*] This is Coding Conversion script'
    print ''
    print '[*] Total Parameters:'
    print '[*] -h --help             get this script help'
    print
    print '[*] File Hash support comparison Hash provided with file hash calculated, it will return Comparison Result'
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
    print
    print '[*] -m --md5_hash         use md5 hash algorithm escape string'
    print 
    print '[*] --sha1_hash           use sha1 hash algorithm escape string'
    print '[*] --sha256_hash         use sha256 hash algorithm escape string'
    print '[*] --sha512_hash         use sha512 hash algorithm escape string'
    print
    print colored('Options Usage:', 'yellow')
    print '[*] python Coding_Conversion.py -f zip_file.zip'
    print '[*] python Coding_Conversion.py -f zip_file.zip [PROVIDE_HASH]'
    print '[*] python Coding_Conversion.py --file_sha1 zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha1 zip_file.zip [PROVIDE_HASH]'
    print '[*] python Coding_Conversion.py --file_sha256 zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha256 zip_file.zip [PROVIDE_HASH]'
    print '[*] python Coding_Conversion.py --file_sha512 zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha512 zip_file.zip [PROVIDE_HASH]'
    print
    print '[*] python Coding_Conversion.py -b "i am your father"'
    print '[*] python Coding_Conversion.py --base64_decode [PROVIDE_HASH]'
    print
    print '[*] python Coding_Conversion.py -u "select * from users"'
    print '[*] python Coding_Conversion.py -url_decode [PROVIDE_HASH]'
    print
    print '[*] python Coding_Conversion.py -e "i am your father"'
    print '[*] python Coding_Conversion.py --hex_decode [PROVIDE_HASH]'
    print 
    print '[*] python Coding_Conversion.py -a "nidaye"'
    print
    print '[*] python Coding_Conversion.py -m "nidaye"'
    print 
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
        banner()
        print colored('Can not handle this options', 'red')
        print colored('Please hit `-h` option to get help !', 'red')
        sys.exit(0)

    for o, a in opts:
        if o in ['-h', '--help']:
            usage()
        elif o in ['-f', '--file_md5']:
            banner()
            md5_hash = hashlib.md5(open(a, 'rb').read()).hexdigest()
            print 'File Name: {}'.format(a)
            print 
            print colored('Calculate Hash Values: {}', 'yellow').format(md5_hash)

            try:
                print colored('Comparison Result: {}', 'magenta').format(md5_hash == args[0])
            except:
                pass

        elif o in ['--file_sha1']:
            banner()
            sha1_hash = hashlib.sha1(open(a, 'rb').read()).hexdigest()
            print 'File Name: {}'.format(a)
            print 
            print colored('Calculate Hash Values: {}', 'yellow').format(sha1_hash)

            try:
                print colored('Comparison Result: {}', 'magenta').format(sha1_hash == args[0])
            except:
                pass


        elif o in ['--file_sha256']:
            banner()
            sha256_hash = hashlib.sha256(open(a, 'rb').read()).hexdigest()
            print 'File Name: {}'.format(a)
            print 
            print colored('Calculate Hash Values: {}', 'yellow').format(sha256_hash)

            try:
                print colored('Comparison Result: {}', 'magenta').format(sha256_hash == args[0])
            except:
                pass

        elif o in ['--file_sha512']:
            banner()
            sha512_hash = hashlib.sha512(open(a, 'rb').read()).hexdigest()
            print 'File Name: {}'.format(a)
            print 
            print colored('Calculate Hash Values: {}', 'yellow').format(sha512_hash)

            try:
                print colored('Comparison Result: {}', 'magenta').format(sha512_hash == args[0])
            except:
                pass

        elif o in ['-b', '--base64_encode']:
            banner()
            base64_str = base64.b64encode(a)
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(base64_str)

        elif o in ['--base64_decode']:
            banner()
            string = a
            base64_str = base64.b64decode(string)
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(base64_str)

        elif o in ['-u', '--url_encode']:
            banner()
            str_encode = re.sub(r'.', lambda m: '%%%s' % m.group(0).encode('hex'), a)
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(str_encode)

        elif o in ['--url_decode']:
            banner()
            str_decode = urllib.unquote(a)
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(str_decode)

        elif o in ['-e', '--hex_encode']:
            banner()
            hex_code = binascii.hexlify(a)
            print 'Raw Data: {}'.format(a)
            print 
            hex_list = []
            index = 0
            for i in hex_code:
                if index%2 == 0:
                    # 偶数
                    if hex_code[index:index+2] != '':
                        hex_list.append(hex_code[index:index+2])
                index += 1
            print colored('Conversion Data(HTML): \\x{}', 'yellow').format('\\x'.join(hex_list))
            print colored('Conversion Data(Others): 0x{}', 'green').format(hex_code)

        elif o in ['--hex_decode']:
            banner()
            print 'Raw Data: {}'.format(a)
            print 
            if a[0] == '0' and a[1] == 'x':
                a = a[2:]
            hex_code = binascii.unhexlify(a)
            print colored('Conversion Data: {}', 'yellow').format(hex_code)

        elif o in ['-a', '--ascii_encode']:
            banner()
            print 'Raw Data: {}'.format(a)
            print 
            ord_string = ''
            for i in range(len(a)):
                if i == 0:
                    ord_string = str(ord(a[i]))
                else:
                    ord_string = ord_string + ' ' + str(ord(a[i]))
            print colored('Conversion Data: {}', 'yellow').format(ord_string)

        elif o in ['-m', '--md5_hash']:
            banner()
            md5_hash = hashlib.md5(a).hexdigest()
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(md5_hash)

        elif o in ['--sha1_hash']:
            banner()
            sha1_hash = hashlib.sha1(a).hexdigest()
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(sha1_hash)

        elif o in ['--sha256_hash']:
            banner()
            sha256_hash = hashlib.sha256(a).hexdigest()
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(sha256_hash)

        elif o in ['--sha512_hash']:
            banner()
            sha512_hash = hashlib.sha512(a).hexdigest()
            print 'Raw Data: {}'.format(a)
            print 
            print colored('Conversion Data: {}', 'yellow').format(sha512_hash)

        else:
            banner()
            print 'Can not handle this options'
            print 'Please use -h get help !'
            sys.exit(0)


if __name__ == '__main__':
    main()
