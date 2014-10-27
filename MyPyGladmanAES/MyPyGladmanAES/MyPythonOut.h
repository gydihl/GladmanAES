/********************************************************************
	created:	2014/10/27
	filename: 	MyPythonOut.h
	author:		dihl
	purpose:	Gladman AES 
*********************************************************************/

/***
Extending and Embedding the Python Interpreter£ºhttp://www.fnal.gov/docs/products/python/v1_5_2/ext/
PyArg_ParseTuple: http://www.fnal.gov/docs/products/python/v1_5_2/ext/parseTuple.html
Py_BuildValue: http://blog.chinaunix.net/uid-22920230-id-3443571.html
***/

#pragma once

#include <Python.h>

#pragma comment(lib, "python27.lib")

#include "GladmanAES/GladmanAES.h"

template <typename T>
void PyDelObject(void *ptr)
{
	T *p = static_cast<T*>(ptr);
	delete p;
}

void PyDelGladmanAES(void *ptr)
{
	GladmanAES *p = static_cast<GladmanAES*>(ptr);
	delete p;
}

// create AES object
PyObject* newAES(PyObject *self, PyObject *args)
{
// 	unsigned char *key;
// 	if (!PyArg_ParseTuple(args, "s", &key))
// 		return NULL;
	GladmanAES *pAES = new GladmanAES;
	// pAES change to PyCObject, and return to python
	return PyCObject_FromVoidPtr(pAES, PyDelObject<GladmanAES>);
}

// set key
PyObject* setkey(PyObject *self, PyObject *args)
{
	PyObject *pyAES = 0;
	unsigned char *key = NULL;
	int length = 0;
	if (!PyArg_ParseTuple(args, "Os#", &pyAES, &key, &length))
		return NULL;
	printf("key length: %d", length);
	// PyObject to void
	void *pTmp = PyCObject_AsVoidPtr(pyAES);
	GladmanAES *pAES = static_cast<GladmanAES*>(pTmp);
	pAES->setkey(key, length);
	return Py_BuildValue("s", key);
}

// encode
PyObject* encode(PyObject *self, PyObject *args)
{
	PyObject *pyAES = 0;
	unsigned char *buf = NULL;
	unsigned long length = 0;
	if (!PyArg_ParseTuple(args, "Os#", &pyAES, &buf, &length))
		return NULL;
	void *pTmp = PyCObject_AsVoidPtr(pyAES);
	GladmanAES *pAES = static_cast<GladmanAES*>(pTmp);
	length = pAES->encode(buf, length, buf);
	return Py_BuildValue("s#", buf, length);
}

// decode
PyObject* decode(PyObject *self, PyObject *args)
{
	PyObject *pyAES = 0;
	unsigned char *buf = NULL;
	unsigned long length = 0;
	if (!PyArg_ParseTuple(args, "Os#", &pyAES, &buf, &length))
		return NULL;
	void *pTmp = PyCObject_AsVoidPtr(pyAES);
	GladmanAES *pAES = static_cast<GladmanAES*>(pTmp);
	length = pAES->decode(buf, length, buf);
	return Py_BuildValue("s#", buf, length);
}

PyObject* test(PyObject *self, PyObject *args)
{
	return NULL;
}