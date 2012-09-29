#include "stdafx.h"

#include <stdio.h>
#include <stdarg.h>

#include <list>
using namespace std;

#include "log.h"

list<string> logs;

void output(const char *fmt, ...)
{
	char buffer[1024];
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsprintf(buffer, fmt, ap);
	va_end(ap);

	printf(buffer);

	logs.push_back(string(buffer));
}
