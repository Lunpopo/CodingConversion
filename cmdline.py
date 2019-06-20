#!/usr/bin/env python
# encoding: utf8
from argparse import ArgumentError
from argparse import ArgumentParser
from argparse import SUPPRESS


class ParseCmd(ArgumentParser):
    def __init__(self):
        pass

    @classmethod
    def parse_cmd(cls):
        """
        ArgumentParser(
            prog=None,
            usage=None,
            description=None,
            epilog=None,
            version=None,
            parents=[],
            formatter_class=HelpFormatter,
            prefix_chars='-',
            fromfile_prefix_chars=None,
            argument_default=None,
            conflict_handler='error',
            add_help=True
        )

        :return: opt object, it`s a dict like
        """

        try:
            parser = ArgumentParser(description='Coding Conversion Script',
                                    usage='python sqlmap [options]', add_help=False)

            helper = parser.add_argument_group("Help Module")
            helper.add_argument('-h', '--help', action='help', default=SUPPRESS,
                                help='show this help message and exit')

            # File Hash of encoding or comparison module
            file_hash = parser.add_argument_group("File Hash Module",
                                                  "File Hash support comparison Hash provided with file hash"
                                                  " calculated, it will return Comparison Result. eg: python "
                                                  "Coding_Conversion.py -f zip_file.zip")
            file_hash.add_argument("-f", '--file-md5', nargs="+", metavar='FILENAME', dest="file_md5",
                                   help="calculate file hash value or compare hash of custom provide, "
                                        "default hash algorithm is md5")
            file_hash.add_argument('--file-sha1', nargs="+", metavar='FILENAME', dest="file_sha1",
                                   help="use sha1 to calculate file hash")
            file_hash.add_argument('--file-sha256', nargs="+", metavar='FILENAME', dest="file_sha256",
                                   help="use sha256 to calculate file hash")
            file_hash.add_argument('--file-sha512', nargs="+", metavar='FILENAME', dest="file_sha512",
                                   help="use sha512 to calculate file hash")

            # String Encoding Module
            file_hash = parser.add_argument_group("String Encoding Module",
                                                  "If the strings of encoding are too long and its contain \' or \". "
                                                  "so you need to use \\ to escape the especially characters.")
            file_hash.add_argument("-b", '--base64-encode', metavar='String', dest="base64_encode",
                                   help="-b option default use base64 encoding'")
            file_hash.add_argument('--base64-decode', metavar='String', dest="base64_decode",
                                   help="--base64-decode option use base64 to decoding the string you given to")
            file_hash.add_argument('-u', '--url-encode', metavar='String', dest="url_encode",
                                   help="-u option default use url encoding")
            file_hash.add_argument('--url-decode', metavar='String', dest="url_decode",
                                   help="--url-decode option decode the string of url you given to")
            file_hash.add_argument('-e', '--hex-encode', metavar='String', dest="hex_encode",
                                   help="-e option use hex to encode this string, -e option default is hex encode")
            file_hash.add_argument('--hex-decode', metavar='String', dest="hex_decode",
                                   help="--hex-decode option use hex decoding module to decode the string you given to")
            file_hash.add_argument('-a', '--ascii-encode', metavar='String', dest="ascii_encode",
                                   help="ascii encoding ")
            file_hash.add_argument('--ascii-decode', metavar='String', dest="ascii_decode", help="ascii decoding ")
            file_hash.add_argument('-m', '--md5-hash', metavar='String', dest="md5_hash",
                                   help="use md5 hash algorithm escape string")
            file_hash.add_argument('--sha1-hash', metavar='String', dest="sha1_hash",
                                   help="use sha1 hash algorithm escape string")
            file_hash.add_argument('--sha256-hash', metavar='String', dest="sha256_hash",
                                   help="use sha256 hash algorithm escape string")
            file_hash.add_argument('--sha512-hash', metavar='String', dest="sha512_hash",
                                   help="use sha512 hash algorithm escape string")

            opts = parser.parse_args()
        except (ArgumentError, TypeError) as e:
            parser.error(e)

        return opts

