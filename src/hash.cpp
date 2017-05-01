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

#include "hash.hpp"

#include <iostream>
#include <string>

#include <openssl/sha.h>
#include <openssl/md5.h>

namespace utils {

std::array<uint8_t, SHA_DIGEST_LENGTH> sha1::calc(const std::string& str) {
	std::array<uint8_t, SHA_DIGEST_LENGTH> hash;
	SHA_CTX hasher;
	SHA_Init(&hasher);
	SHA_Update(&hasher, str.data(), str.size());
	SHA_Final(hash.data(), &hasher);
	return hash;
}

const std::string itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" ;
const std::string hash_prefix = "$H$";

std::array<uint8_t, MD5_DIGEST_LENGTH> md5::calc(const std::string& input) {
	std::array<uint8_t, MD5_DIGEST_LENGTH> hash;
	MD5_CTX md5_worker;
	MD5_Init(&md5_worker);
	MD5_Update(&md5_worker, input.data(), input.size());
	MD5_Final(hash.data(), &md5_worker);
	return hash;
}

int md5::get_iteration_count(const std::string& hash) {
	return itoa64.find_first_of(hash[3]);
}

std::string md5::get_salt(const std::string& hash) {
	return hash.substr(4,8);
}

bool md5::is_valid_hash(const std::string& hash) {
	if(hash.size() != 34) return false;
	if(hash.substr(0,3) != hash_prefix) return false;

	const int iteration_count = get_iteration_count(hash);
	if(iteration_count < 7 || iteration_count > 30) return false;

	return true;
}

template<size_t len>
std::string encode_hash(const std::array<uint8_t, len>& input) {
	std::string encoded_hash;

	unsigned int i = 0;
	do {
		unsigned value = input[i++];
		encoded_hash.append(itoa64.substr(value & 0x3f,1));
		if(i < len)
			value |= static_cast<int>(input[i]) << 8;
		encoded_hash.append(itoa64.substr((value >> 6) & 0x3f,1));
		if(i++ >= len)
			break;
		if(i < len)
			value |= static_cast<int>(input[i]) << 16;
		encoded_hash.append(itoa64.substr((value >> 12) & 0x3f,1));
		if(i++ >= len)
			break;
		encoded_hash.append(itoa64.substr((value >> 18) & 0x3f,1));
	} while (i < len);

	return encoded_hash;
}

std::string md5::create_hash(const std::string& password, const std::string& salt, int iteration_count) {
	iteration_count = 1 << iteration_count;

	std::array<uint8_t, 16> output = md5::calc(salt + password);
	do {
		output = md5::calc(std::string(output.begin(), output.end()).append(password));
	} while(--iteration_count);

	return encode_hash(output);
}

} // namespace utils
