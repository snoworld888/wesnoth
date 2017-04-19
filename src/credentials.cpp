/*
Copyright (C) 2017 by the Battle for Wesnoth Project http://www.wesnoth.org/

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY.

See the COPYING file for more details.
*/

#include "credentials.hpp"

#include "preferences.hpp"
#include "serialization/unicode.hpp"
#include "filesystem.hpp"
#include "log.hpp"

#include <algorithm>
#include <sstream>

#ifdef _WIN32
#include <boost/range/iterator_range.hpp>
#include <windows.h>
#endif

static lg::log_domain log_config("config");
#define ERR_CFG LOG_STREAM(err , log_config)

static std::string credentials;

static std::string encrypt(const std::string& text, const std::string& key);
static std::string decrypt(const std::string& text, const std::string& key);
static std::string build_key(const std::string& server, const std::string& login);
static std::string escape(const std::string& text);
static std::string unescape(const std::string& text);

static std::string get_system_username() {
	std::string res;
#ifdef _WIN32
	wchar_t buffer[300];
	DWORD size = 300;
	if(GetUserNameW(buffer, &size)) {
		//size includes a terminating null character.
		assert(size > 0);
		res = unicode_cast<utf8::string>(boost::iterator_range<wchar_t*>(buffer, buffer + size - 1));
	}
#else
	if(char* const login = getenv("USER")) {
		res = login;
	}
#endif
	return res;
}

static const std::string EMPTY_LOGIN = "@@";

namespace preferences {
	std::string login()
	{
		std::string name = preferences::get("login", EMPTY_LOGIN);
		if(name == EMPTY_LOGIN) {
			name = get_system_username();
		} else if(name.size() > 2 && name[0] == '@' && name[name.size() - 1] == '@') {
			name = name.substr(1, name.size() - 2);
		} else {
			ERR_CFG << "malformed user credentials (did you manually edit the preferences file?)" << std::endl;
		}
		if(name.empty()) {
			return "player";
		}
		return name;
	}

	void set_login(const std::string& login)
	{
		preferences::set("login", '@' + login + '@');
	}

	bool remember_password() {
		return preferences::get("remember_password", false);
	}

	void set_remember_password(bool remember) {
		preferences::set("remember_password", remember);

		std::fill(credentials.begin(), credentials.end(), '\0');
		if(remember) {
			load_credentials();
		} else {
			credentials.clear();
		}
	}

	std::string password(const std::string& server, const std::string& login)
	{
		if(!remember_password()) {
			return decrypt(credentials, build_key(server, login));
		}
		std::string lookup = '\xc' + login + '@' + server + '=';
		assert(lookup.back() == 0);
		std::string temp = decrypt(credentials, build_key("*.*", get_system_username()));
		size_t pos = temp.find(lookup);
		// Example:
		// temp = "\xcabc@xyz.org\0uuuuuu\xcxyz@abc.net\0uuuuuu\xc"
		// lookup = "\xcxyz@abc.net\0"
		// pos = 19
		// lookup.size() = 13
		// pos2 = 38
		// pos2 - pos - lookup.size() = 6
		if(pos == std::string::npos) {
			std::fill(temp.begin(), temp.end(), '\0');
			return "";
		}
		size_t pos2 = temp.find('\xc', pos + lookup.size() - 1);
		if(pos2 == std::string::npos) {
			std::fill(temp.begin(), temp.end(), '\0');
			return "";
		}
		std::string pass = temp.substr(pos + lookup.size(), pos2 - pos - lookup.size());
		std::fill(temp.begin(), temp.end(), '\0');
		return decrypt(unescape(pass), build_key(server, login));
	}

	void set_password(const std::string& server, const std::string& login, const std::string& key)
	{
		if(!remember_password()) {
			credentials = encrypt(key, build_key(server, login));
			return;
		}
		std::string lookup = '\xc' + login + '@' + server + '=';
		assert(lookup.back() == 0);
		std::string temp = decrypt(credentials, build_key("*.*", get_system_username()));
		std::string pass = escape(encrypt(key, build_key(server, login)));
		size_t pos = temp.find(lookup);
		if(pos == std::string::npos) {
			while(!temp.empty() && temp.back() == '\xc') {
				temp.pop_back();
			}
			std::copy(lookup.begin(), lookup.end(), std::back_inserter(temp));
			std::copy(pass.begin(), pass.end(), std::back_inserter(temp));
			temp.push_back('\xc');
			credentials = encrypt(temp, build_key("*.*", get_system_username()));
			std::fill(temp.begin(), temp.end(), '\0');
			return;
		}
		size_t pos2 = temp.find('\xc', pos + lookup.size() - 1);
		if(pos2 == std::string::npos) {
			// TODO: Not sure if this is the right thing to do in this case (or if there's even anything that CAN be done in this case)
			std::copy(pass.begin(), pass.end(), std::back_inserter(temp));
			temp.push_back('\xc');
			credentials = encrypt(temp, build_key("*.*", get_system_username()));
			std::fill(temp.begin(), temp.end(), '\0');
			return;
		}
		temp.replace(pos + lookup.size(), pos2 - pos - lookup.size(), pass);
		credentials = encrypt(temp, build_key("*.*", get_system_username()));
		std::fill(temp.begin(), temp.end(), '\0');
	}

	void load_credentials()
	{
		if(!remember_password()) {
			return;
		}
		// Credentials are in a different file, which is a binary blob
		filesystem::scoped_istream stream = filesystem::istream_file(filesystem::get_credentials_file(), false);
		stream->seekg(0, std::ios::end);
		credentials.clear();
		credentials.reserve(stream->tellg());
		stream->seekg(0, std::ios::beg);
		stream->clear();
		credentials.assign(std::istreambuf_iterator<char>(*stream), std::istreambuf_iterator<char>());
	}

	void save_credentials()
	{
		if(remember_password()) {
			try {
				filesystem::scoped_ostream credentials_file = filesystem::ostream_file(filesystem::get_credentials_file());
				std::copy(credentials.begin(), credentials.end(), std::ostreambuf_iterator<char>(*credentials_file));
			} catch(filesystem::io_exception&) {
				ERR_CFG << "error writing to credentials file '" << filesystem::get_credentials_file() << "'" << std::endl;
			}
		} else {
			filesystem::delete_file(filesystem::get_credentials_file());
		}
	}
}

// TODO: No idea if this is a reasonable way of generating the key.
std::string build_key(const std::string& server, const std::string& login) {
	std::ostringstream out;
	out << '\x2' << login << "\x3wesnoth\x5" << server << '\x7' << get_system_username() << '\xb';
	return out.str();
}

// FIXME: XOR encryption is a really terrible choice - swap it out for something better!
static std::string xor_crypt(std::string text, const std::string& key)
{
	const size_t m = key.size();
	for(size_t i = 0; i < text.size(); i++) {
		text[i] ^= key[i % m];
	}
	return text;
}

std::string encrypt(const std::string& text, const std::string& key)
{
	return xor_crypt(text, key);
}

std::string decrypt(const std::string& text, const std::string& key)
{
	return xor_crypt(text, key);
}

std::string unescape(const std::string& text) {
	std::string unescaped;
	unescaped.reserve(text.size());
	bool escaping = false;
	for(char c : text) {
		if(escaping) {
			if(c == '\xa') {
				unescaped.push_back('\xc');
			} else {
				unescaped.push_back(c);
			}
			escaping = false;
		} else if(c == '\x1') {
			escaping = true;
		} else {
			unescaped.push_back(c);
		}
	}
	return unescaped;
}

std::string escape(const std::string& text) {
	std::string escaped;
	escaped.reserve(text.size());
	for(char c : text) {
		if(c == '\x1') {
			escaped += "\x1\x1";
		} else if(c == '\xc') {
			escaped += "\x1\xa";
		} else {
			escaped.push_back(c);
		}
	}
	return escaped;
}
