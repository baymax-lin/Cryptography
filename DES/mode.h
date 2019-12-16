#pragma once
#include <bitset>
#include <string>
#include <vector>
#include "base.h"
using namespace std;

/*
 example :des expansion (ecb cbc cfb ofb)
 author :lx
*/
class ecb : public des{
	public:
		ecb();
		~ecb();
		bool encryptByDES(string str,string key,vector<bitset<64>> &ciphers);
		bool decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret);
};


class cbc : public des{
	public:
		cbc();
		~cbc();
		bool encryptByDES(string str,string key,vector<bitset<64>> &ciphers);
		bool decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret);
};

class cfb : public des{
	public:
		cfb();
		~cfb();
		bool encryptByDES(string str,string key,vector<bitset<64>> &ciphers);
		bool decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret);
};


class ofb : public des{
	public:
		ofb();
		~ofb();
		bool encryptByDES(string str,string key,vector<bitset<64>> &ciphers);
		bool decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret);
		bool encryptByStreamingDES(string str,string key,vector<bitset<8>> &ciphers);
		bool decryptByStreamingDES(vector<bitset<8>> &ciphers, string key,string &ret);		
};



