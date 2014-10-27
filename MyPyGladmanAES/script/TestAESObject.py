#coding: utf-8
#__author__ = 'gydihl'

from MyGladmanAESObject import *

# 7d72e6035fd27ebcd25f1a4daec1bef6

myAES = MyGladmanAESObject()
myAES.setkey('7d72e6035fd27ebcd25f1a4daec1bef67d72e6035fd27ebcd25f1a4daec1bef6')

fileOrg = open(r'D:\gameloading.json', 'rb')
fileEncode = open(r'D:\gameloading_1.json', 'wb+')
fileDecode = open(r'D:\gameloading_1_1.json', 'wb+')

try:
    chunk = fileOrg.read()

    chunkEncode = myAES.encode(chunk)
    fileEncode.write(chunkEncode)

    chunkDecode = myAES.decode(chunkEncode)
    fileDecode.write(chunkDecode)
finally:
    fileOrg.close()
    fileEncode.close()
    fileDecode.close()


