#include "console.h"

#include <core/os/os.h>

#include <iostream>
#include <string>



#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
#include <windows.h>

static bool is_cin_key() {
	int key_read = false;
	HANDLE input_handle = GetStdHandle(STD_INPUT_HANDLE);
	if (input_handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "GetStdHandle failed (error %lu)\n", GetLastError());
		return false;
	}
	DWORD events = 0;
	INPUT_RECORD input_record;

	PeekConsoleInput(input_handle, &input_record, 1, &events);
	if (events > 0) {
		if (input_record.EventType == KEY_EVENT) {
			if (input_record.Event.KeyEvent.bKeyDown) {
				//std::cout << "keydown" << std::endl;
				key_read = true;
			}
		}

		if (!key_read) {
			ReadConsoleInput(input_handle, &input_record, 1, &events);
		}

	}

	return key_read;

}

static bool get_console_mode(DWORD *mode) {
	HANDLE input_handle = GetStdHandle(STD_INPUT_HANDLE);
	if (input_handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "GetStdHandle failed (error %lu)\n", GetLastError());
		return false;
	}

	if (!GetConsoleMode(input_handle, mode)) {
		fprintf(stderr, "GetConsoleMode failed (error %lu)\n", GetLastError());
		return false;
	}
	return true;
}

static bool set_console_mode(DWORD mode) {
	HANDLE input_handle = GetStdHandle(STD_INPUT_HANDLE);
	if (input_handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "GetStdHandle failed (error %lu)\n", GetLastError());
		return false;
	}

	if (!SetConsoleMode(input_handle, mode)) {
		fprintf(stderr, "GetConsoleMode failed (error %lu)\n", GetLastError());
		return false;
	}

	return true;
}

static void set_input_echo(bool do_echo) {
	DWORD mode;
	if (!get_console_mode(&mode)) {
		return;
	}
	if (do_echo) {
		mode |= ENABLE_ECHO_INPUT;
	} else {
		mode &= ~((DWORD)ENABLE_ECHO_INPUT);
	}
	set_console_mode(mode);
}

#else // #ifdef _WIN32
#include <unistd.h>
#include <cstdlib>
#include <termios.h>

static bool is_cin_key() {
	struct termios new_term_info, old_term_info

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	fd_set savefds = readfds;

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	bool is_input = (select(1, &readfds, NULL, NULL, &timeout));
	readfds = savefds;
	return is_input;
}

static bool get_console_mode(termios *mode) {

}

#endif // #else _WIN32


String get_gdstring_from_console(bool echo_input, uint64_t timeout_ms) {
	uint64_t start_time;
	String return_str;
	std::string input_str;
	bool done = false;
	std::cout.flush();
	std::cin.clear();

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
	DWORD old_mode = 0;
	bool console_okay = get_console_mode(&old_mode);
	if (console_okay) set_input_echo(echo_input);
#endif

	if (timeout_ms > 0) {
		start_time = OS::get_singleton()->get_system_time_msecs();
	}
	while (!done) {
		OS::get_singleton()->delay_usec(10000);
		if (is_cin_key()) {
			char chr = 0;
			while (chr != '\n' && chr != '\r') {
				std::cin.get(chr);
				return_str += chr;
				start_time = OS::get_singleton()->get_system_time_msecs();
			}
			done = true;
		}
		if (timeout_ms > 0) {
			done |= !(OS::get_singleton()->get_system_time_msecs() - start_time < timeout_ms);
		}
	}

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
 if (console_okay) set_console_mode(old_mode);
#else

#endif
	return return_str;
}
