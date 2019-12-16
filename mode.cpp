#include "base.h"
#include "mode.h"
#include<bitset>
#include<fstream>
#include <iostream>
#include <string>
#include <vector>
typedef long long LL;
using namespace std;
#define rep(a,b,c) for(int a=b;a<=c;++a)

/*
 example :des expansion (ecb cbc cfb ofb)
 author :lx
*/

ecb::ecb()
{
	
}
ecb::~ecb()
{
	
}
bool ecb::encryptByDES(string str,string key,vector<bitset<64>> &ciphers){
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	cutStringByBlock(str);	
	ciphers.clear();
	rep(i,0,block_num-1){
		bitset<64> bitStr = char_to_bit(pStrings[i].c_str());
		ciphers.push_back (des_encrypt(bitStr));
	}
	return true;		
}

bool ecb::decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret){
	string temp;
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	
	rep(i,0,ciphers.size()-1){
		bitset<64> ans = des_decrypt(ciphers[i]);
		rep(k,0,7){
			char cc = 0;
			rep(j,0,7) if (ans[k*8+j]) cc |= (1<<(7-j));
			temp += cc;
		}
	}
	ret = temp;
	return true;	
}



cbc::cbc()
{
	
}
cbc::~cbc()
{
	
}

bool cbc::encryptByDES(string str,string key,vector<bitset<64>> &ciphers){
	LL initVector = 0x00;
	bitset<64> iv (initVector); //bitset cannot be initialized by 64bits
	iv = change(iv);
	
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	cutStringByBlock(str);	
	ciphers.clear();
		
	rep(i,0,block_num-1){
		bitset<64> ans = char_to_bit(pStrings[i].c_str());
		ans = iv ^ ans;
		iv = des_encrypt(ans);
		ciphers.push_back(iv);
	}
	return true;
}

bool cbc::decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret){
	LL initVector = 0x00;
	bitset<64> iv (initVector);
	iv = change(iv);

	if (key.length() != 8) return false;
	gnrSubKeys(key);
	
	string temp;
	rep(i,0,ciphers.size() -1){
		bitset<64> ans = des_decrypt(ciphers[i]);
		ans = ans ^ iv;
		rep(k,0,7){
			char cc = 0;
			rep(j,0,7) if (ans[k*8+j]) cc |= (1<<(7-j));
			temp += cc;
		}	
		iv = ciphers[i];	
	}
	ret = temp;
	return true;
}




cfb::cfb()
{
	
}
cfb::~cfb()
{
	
}

bool cfb::encryptByDES(string str,string key,vector<bitset<64>> &ciphers){
	LL initVector = 0x00;
	bitset<64> iv (initVector); //bitset cannot be initialized by 64bits
	iv = change(iv);
	
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	cutStringByBlock(str);	
	ciphers.clear();
		
	rep(i,0,block_num-1){
		bitset<64> ans = des_encrypt(iv);
		iv = ans ^ char_to_bit(pStrings[i].c_str());
		ciphers.push_back(iv);
	}
	return true;
}

bool cfb::decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret){
	LL initVector = 0x00;
	bitset<64> iv (initVector);
	iv = change(iv);
	
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	
	string temp;
	rep(i,0,ciphers.size() -1){
		bitset<64> ans = des_encrypt(iv);
		ans = ans ^ ciphers[i];
		rep(k,0,7){
			char cc = 0;
			rep(j,0,7) if (ans[k*8+j]) cc |= (1<<(7-j));
			temp += cc;
		}	
		iv = ciphers[i];	
	}
	ret = temp;
	return true;
}


ofb::ofb()
{
	
}
ofb::~ofb()
{
	
}

bool ofb::encryptByDES(string str,string key,vector<bitset<64>> &ciphers){
	LL initVector = 0x00;
	bitset<64> iv (initVector); //bitset cannot be initialized by 64bits
	iv = change(iv);
	
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	cutStringByBlock(str);	
	ciphers.clear();
		
	rep(i,0,block_num-1){
		iv = des_encrypt(iv);
		bitset<64> ans = iv ^ char_to_bit(pStrings[i].c_str());
		ciphers.push_back(ans);
	}
	return true;
}

bool ofb::decryptByDES(vector<bitset<64>> &ciphers, string key,string &ret){
	LL initVector = 0x00;
	bitset<64> iv (initVector);
	iv = change(iv);
	
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	
	string temp;
	rep(i,0,ciphers.size() -1){
		iv = des_encrypt(iv);
		bitset<64> ans = iv ^ ciphers[i];
		rep(k,0,7){
			char cc = 0;
			rep(j,0,7) if (ans[k*8+j]) cc |= (1<<(7-j));
			temp += cc;
		}
	}
	ret = temp;
	return true;
}

bool ofb::encryptByStreamingDES(string str,string key,vector<bitset<8>> &ciphers){
	LL initVector = 0x00;
	bitset<64> iv (initVector); //bitset cannot be initialized by 64bits
	iv = change(iv);
	
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	cutStringByBlock(str);	
	ciphers.clear();
		
	rep(i,0,str.length()-1){
		bitset<8> leftmost;
		bitset<64>iv_tmp = des_encrypt(iv);
		rep(j,0,7) leftmost[j] = iv_tmp[j];
		bitset<8> ans = leftmost ^ char_to_bit8(str[i]);
		iv >>= 8;// iv has been inverse, so right shift is equal to left shift currently.
		rep(j,56,63) iv[j] = leftmost[j-56];
		ciphers.push_back(ans);
	}
	return true;	
}
bool ofb::decryptByStreamingDES(vector<bitset<8>> &ciphers, string key,string &ret){
	LL initVector = 0x00;
	bitset<64> iv (initVector);
	iv = change(iv);
	
	if (key.length() != 8) return false;
	gnrSubKeys(key);
	
	string temp;
	rep(i,0,ciphers.size() -1){
		bitset<8> leftmost;
		bitset<64>iv_tmp = des_encrypt(iv);
		rep(j,0,7) leftmost[j] = iv_tmp[j];
		bitset<8> ans = leftmost ^ ciphers[i];
		char cc = 0;
		rep(j,0,7) if (ans[j]) cc |= (1<<(7-j));
		temp += cc;
		iv >>= 8;// iv has been inverse, so right shift is equal to left shift currently.
		rep(j,56,63) iv[j] = leftmost[j-56]; // or
	}
	ret = temp;
	return true;	
}
