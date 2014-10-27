#coding: utf-8
#__author__ = 'gydihl'

import MyPyGladmanAES

class MyGladmanAESObject(object):
    def __init__(self):
        self._aes = MyPyGladmanAES.newAES()

    def setkey(self, key):
        self._key = key
        MyPyGladmanAES.setkey(self._aes, self._key)

    def encode(self, buff):
        length = 16
        count = len(buff)
        add = length-count%length + length
        buff = buff + '\0'*add
        return MyPyGladmanAES.encode(self._aes, buff)

    def decode(self, buff):
        decode = MyPyGladmanAES.decode(self._aes, buff)
        return  decode.rstrip('\0')


