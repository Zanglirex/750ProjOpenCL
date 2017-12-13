#pragma once
#ifndef _CLINFO_H
#define _CLINFO_H

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

#include "CL/cl.h"

static const char * CLErrString(cl_int status);
static void PrintDevice(cl_device_id device);
static void PrintPlatform(cl_platform_id platform);
int print_clinfo();

#endif //_CLINFO_H
