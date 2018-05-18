import hashlib
import sys
import getopt
import base64
import urllib
import binascii


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
    print '[*] --file_sha254         use sha254 to calculate file hash'
    print
    print '[*] -b --base64_encode    -s option default is base64 encode'
    print '[*] --base64_decode'
    print
    print '[*] -u --url_encode       url encode, -u option default is url encode'
    print '[*] --url_decode'
    print
    print '[*] -e --hex_encode       use hex to encode this string,'
    print '                          -e option default is hex encode'
    print '[*] -e --hex_decode'
    print
    print 'Usage:'
    print '[*] python Coding_Conversion.py -f zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha1 zip_file.zip'
    print '[*] python Coding_Conversion.py --file_sha254 zip_file.zip'
    print
    print '[*] python Coding_Conversion.py -b "i am your father"'
    print '[*] python Coding_Conversion.py --base64_decode "aSBhbSB5b3VyIGZhdGhlcg=="'
    print
    print '[*] python Coding_Conversion.py -u "select * from users"'
    print '[*] python Coding_Conversion.py -url_decode "select%20%2A%20from%20users"'
    print
    print '[*] python Coding_Conversion.py -e "i am your father"'
    print '[*] python Coding_Conversion.py --hex_decode "6920616d20796f757220666174686572"'
    sys.exit(0)


def main():

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hf:b:u:e:', [
            'help',
            'file_md5=',
            'file_sha1=',
            'file_sha256=',
            'base64_encode=',
            'base64_decode=',
            'url_encode=',
            'url_decode=',
            'hex_encode=',
            'hex_decode=',
        ])
    except:
        usage()

    for o, a in opts:
        if o in ['-h', '--help']:
            usage()
        elif o in ['-f', '--file_md5']:
            md5_hash = hashlib.md5(open(a, 'rb').read()).hexdigest()
            print 'File Name: ', a
            print 'Calculate Hash Values: ', md5_hash

        elif o in ['--file_sha1']:
            sha1_hash = hashlib.sha1(open(a, 'rb').read()).hexdigest()
            print 'File Name: ', a
            print 'Calculate Hash Values: ', sha1_hash

        elif o in ['--file_sha256']:
            sha256_hash = hashlib.sha256(open(a, 'rb').read()).hexdigest()
            print 'File Name: ', a
            print 'Calculate Hash Values', sha256_hash

        elif o in ['-b', '--base64_encode']:
            base64_str = base64.b64encode(a)
            print 'Raw Data: ', a
            print 'Conversion Data', base64_str

        elif o in ['--base64_decode']:
            string = a
            base64_str = base64.b64decode(string)
            print 'Raw Data: ', a
            print 'Conversion Data: ', base64_str

        elif o in ['-u', '--url_encode']:
            str_encode = urllib.quote(a)
            print 'Raw Data: ', a
            print 'Conversion Data: ', str_encode

        elif o in ['--url_decode']:
            str_decode = urllib.unquote(a)
            print 'Raw Data: ', a
            print 'Conversion Data: ', str_decode

        elif o in ['-e', '--hex_encode']:
            hex_code = binascii.hexlify(a)
            print 'Raw Data: ', a
            print 'Conversion Data: ', hex_code

        elif o in ['--hex_decode']:
            hex_code = binascii.unhexlify(a)
            print 'Raw Data: ', a
            print 'Conversion Data: ', hex_code

        else:
            print 'Can not handle this options'
            print 'Please use -h get help !'
            sys.exit(0)


if __name__ == '__main__':
    main()
