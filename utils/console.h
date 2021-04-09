#ifndef CONSOLE_H
#define CONSOLE_H

#include <core/ustring.h>

#include <vector>
#include <cstdint>


String get_gdstring_from_console(bool echo_input = false, uint64_t timeout_ms = 0);

#endif // !CONSOLE_H
