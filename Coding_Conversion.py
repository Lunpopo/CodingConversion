#!/usr/bin/env python
# encoding: utf8
import hashlib
# 专门处理命令行参数的类
from cmdline import ParseCmd
import sys
import base64
import urllib
import binascii
import re
import subprocess
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
| |    / _ \ / _` | | '_ \ / _` | |    / _ \| '_ \ \ / / _ \ '__/ __| |/ _ \| '_ \\
| \__/\ (_) | (_| | | | | | (_| | \__/\ (_) | | | \ V /  __/ |  \__ \ | (_) | | | |
 \____/\___/ \__,_|_|_| |_|\__, |\____/\___/|_| |_|\_/ \___|_|  |___/_|\___/|_| |_|
                            __/ |
                           |___/
    \033[0m'''


def main():
    # 如果任何参数都没有的情况下
    if not len(sys.argv[1:]):
        popen = subprocess.Popen('python {} -h'.format(sys.argv[0]), shell=True, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, code = popen.communicate()
        print output
    else:
        banner()

        # cmdline() 处理所有的 command line 参数, 并全部存入 opt 中返回
        opt = ParseCmd.parse_cmd(sys.argv[0])
        if opt.file_md5:
            md5_hash = hashlib.md5(open(opt.file_md5[0], 'rb').read()).hexdigest()
            print 'File Name: {}'.format(opt.file_md5[0])
            print
            print colored('Calculate Hash Values: {}', 'yellow').format(md5_hash)
            try:
                print colored('Comparison Result: {}', 'magenta').format(md5_hash == opt.file_md5[1])
            except:
                pass

        if opt.file_sha1:
            sha1_hash = hashlib.sha1(open(opt.file_sha1[0], 'rb').read()).hexdigest()
            print 'File Name: {}'.format(opt.file_sha1[0])
            print
            print colored('Calculate Hash Values: {}', 'yellow').format(sha1_hash)
            try:
                print colored('Comparison Result: {}', 'magenta').format(sha1_hash == opt.file_sha1[1])
            except:
                pass

        if opt.file_sha256:
            sha256_hash = hashlib.sha256(open(opt.file_sha256[0], 'rb').read()).hexdigest()
            print 'File Name: {}'.format(opt.sha256_hash[0])
            print
            print colored('Calculate Hash Values: {}', 'yellow').format(sha256_hash)
            try:
                print colored('Comparison Result: {}', 'magenta').format(sha256_hash == opt.file_sha256[1])
            except:
                pass

        if opt.file_sha512:
            sha512_hash = hashlib.sha512(open(opt.file_sha512[0], 'rb').read()).hexdigest()
            print 'File Name: {}'.format(opt.file_sha512[0])
            print
            print colored('Calculate Hash Values: {}', 'yellow').format(sha512_hash)
            try:
                print colored('Comparison Result: {}', 'magenta').format(sha512_hash == opt.file_sha512[1])
            except:
                pass

        if opt.base64_encode:
            base64_str = base64.b64encode(opt.base64_encode)
            print 'Raw Data: {}'.format(opt.base64_encode)
            print
            print colored('Conversion Data: {}', 'yellow').format(base64_str)

        if opt.base64_decode:
            try:
                base64_str = base64.b64decode(opt.base64_decode)
                print 'Raw Data: {}'.format(opt.base64_decode)
                print
                print colored('Conversion Data: {}', 'yellow').format(base64_str)
            except Exception as e:
                print colored("Can not decode the string you given to", 'red')
                print colored(e, 'red')

        if opt.url_encode:
            str_encode = re.sub(r'.', lambda m: '%%%s' % m.group(0).encode('hex'), opt.url_encode)
            print 'Raw Data: {}'.format(opt.url_encode)
            print
            print colored('Conversion Data: {}', 'yellow').format(str_encode)

        if opt.url_decode:
            str_decode = urllib.unquote(opt.url_decode)
            print 'Raw Data: {}'.format(opt.url_decode)
            print
            print colored('Conversion Data: {}', 'yellow').format(str_decode)

        if opt.hex_encode:
            hex_code = binascii.hexlify(opt.hex_encode)
            print 'Raw Data: {}'.format(opt.hex_encode)
            print
            hex_list = []
            index = 0
            for _ in hex_code:
                if index % 2 == 0:
                    # 偶数
                    if hex_code[index:index+2] != '':
                        hex_list.append(hex_code[index:index+2])
                index += 1
            print colored('Conversion Data(HTML): \\x{}', 'yellow').format('\\x'.join(hex_list))
            print colored('Conversion Data(Others): 0x{}', 'green').format(hex_code)

        if opt.hex_decode:
            try:
                print 'Raw Data: {}'.format(opt.hex_decode)
                print
                if opt.hex_decode[0] == '0' and opt.hex_decode[1] == 'x':
                    opt.hex_decode = opt.hex_decode[2:]
                elif opt.hex_decode[0] == '\\' and opt.hex_decode[1] == 'x':
                    opt.hex_decode = opt.hex_decode.replace('\\x', '')

                hex_code = binascii.unhexlify(opt.hex_decode)
                print colored('Conversion Data: {}', 'yellow').format(hex_code)
            except Exception as e:
                print colored("Can not decode the string you given to", 'red')
                print colored(e, 'red')

        if opt.ascii_encode:
            print 'Raw Data: {}'.format(opt.ascii_encode)
            print
            ord_string = ' '.join([str(ord(_)) for _ in opt.ascii_encode])
            print colored('Conversion Data: {}', 'yellow').format(ord_string)

        if opt.ascii_decode:
            try:
                print 'Raw Data: {}'.format(opt.ascii_decode)
                print
                chr_string = ''.join([chr(int(_)) for _ in opt.ascii_decode.split()])
                print colored('Conversion Data: {}', 'yellow').format(chr_string)
            except Exception as e:
                print colored("Can not decode the string you given to", 'red')
                print colored(e, 'red')

        if opt.md5_hash:
            md5_hash = hashlib.md5(opt.md5_hash).hexdigest()
            print 'Raw Data: {}'.format(opt.md5_hash)
            print
            print colored('Conversion Data: {}', 'yellow').format(md5_hash)

        if opt.sha1_hash:
            sha1_hash = hashlib.sha1(opt.sha1_hash).hexdigest()
            print 'Raw Data: {}'.format(opt.sha1_hash)
            print
            print colored('Conversion Data: {}', 'yellow').format(sha1_hash)

        if opt.sha256_hash:
            sha256_hash = hashlib.sha256(opt.sha256_hash).hexdigest()
            print 'Raw Data: {}'.format(opt.sha256_hash)
            print
            print colored('Conversion Data: {}', 'yellow').format(sha256_hash)

        if opt.sha512_hash:
            sha512_hash = hashlib.sha512(opt.sha512_hash).hexdigest()
            print 'Raw Data: {}'.format(opt.sha512_hash)
            print
            print colored('Conversion Data: {}', 'yellow').format(sha512_hash)

if __name__ == '__main__':
    main()
