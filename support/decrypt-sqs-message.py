import base64
import json
import logging
import traceback
import zlib
import six

# SQS message that you want to decrypt
f = "eJztVltv4kYUfs+vG74="

def process_sqs_message():
    sqs_message = zlib.decompress(base64.b64decode(f))
    print (sqs_message)

process_sqs_message()