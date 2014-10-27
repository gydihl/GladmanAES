// MyPyGladmanAES.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#include <python.h>

#pragma comment(lib, "python27.lib")

#include "MyPythonOut.h"

static PyMethodDef GladmanAESMethods[] = {
	{"test", test, METH_VARARGS},
	{"newAES", newAES, METH_VARARGS},
	{"setkey", setkey, METH_VARARGS},
	{"encode", encode, METH_VARARGS},
	{"decode", decode, METH_VARARGS},
	{NULL, NULL, NULL}
};

PyMODINIT_FUNC initMyPyGladmanAES()
{
	Py_InitModule("MyPyGladmanAES", GladmanAESMethods);
}
