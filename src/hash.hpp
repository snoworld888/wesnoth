/*
   Copyright (C) 2008 - 2017 by Thomas Baumhauer <thomas.baumhauer@NOSPAMgmail.com>
   Part of the Battle for Wesnoth Project http://www.wesnoth.org/

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY.

   See the COPYING file for more details.
*/

#ifndef HASH_HPP_INCLUDED
#define HASH_HPP_INCLUDED

#include <array>
#include <cstdint>
#include <string>

namespace utils {

template<size_t len>
std::string encode_hash(const std::array<uint8_t, len>& input);

namespace md5 {
/**
 * Returns the MD5 digest for the specified input.
 *
 * @note The returned value points to a fixed-size 16 bytes array representing
 *       the raw MD5 value, not a null-terminated string. Use encode_hash if
 *       you need the text representation instead.
 */
std::array<uint8_t, 16> calc(const std::string& input);
int get_iteration_count(const std::string& hash);
std::string get_salt(const std::string& hash);
bool is_valid_hash(const std::string& hash);
std::string create_hash(const std::string& password, const std::string& salt, int iteration_count =10);
}
template std::string encode_hash<16>(const std::array<uint8_t, 16>& input);

namespace sha1 {
std::array<uint8_t, 20> calc(const std::string& input);
}
template std::string encode_hash<20>(const std::array<uint8_t, 20>& input);

} // namespace utils

#endif // HASH_HPP_INCLUDED
