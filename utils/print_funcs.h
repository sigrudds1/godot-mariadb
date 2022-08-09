#ifndef PRINT_FUNCS_H
#define PRINT_FUNCS_H

#include <iomanip> //for std::setw
#include <iostream> //for std::cout

template <typename T>
void print_arr_hex(T arr, size_t len, bool endl) {
	//std::cout //<< std::showbase // show the 0x prefix
	//		  << std::internal // fill between the prefix and the number
	std::cout << std::setfill('0');
	for (size_t i = 0; i < len; ++i) {
		std::cout << std::hex << std::setw(2) << static_cast<int>(arr[i]);
	}
	if (endl)
		std::cout << std::endl;
}

#endif // !PRINT_FUNCS_H
