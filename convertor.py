import base64, re
from binascii import unhexlify
from keystone import *
from capstone import *

def b64_convert(string, isBase64):
    if isBase64:
        stringBytes = string.encode("ascii")
        b64Bytes = base64.b64decode(stringBytes)
        b64String = b64Bytes.decode("ascii")

        return b64String
    
    else:
        stringBytes = string.encode("ascii")
        b64Bytes = base64.b64encode(stringBytes)
        b64String = b64Bytes.decode("ascii")

        return b64String

############################ Assembly Related ###############################
