#include "base.h"
#include<bitset>
#include<fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

/*
 example :des base
 modified by :lx
*/

des::des()
{
	
}
 
 
des::~des()
{
	
}
 
bitset<32> des::F(bitset<32> R, bitset<48> k) {
	//E盒扩展
	bitset<48> expandR;  
	for (int i = 0; i < 48; i++)
		expandR[47 - i] = R[32 - E[i]];  //expandR[i] = R[E[i] - 1];
	//异或
	expandR = expandR ^ k;
	//S盒代替
	bitset<32> output;
	int x = 0;
	for (int i = 0; i < 48; i = i + 6)
	{
		int row = expandR[i] * 2 + expandR[i + 5];
		int col = expandR[i + 1] * 8 + expandR[i + 2] * 4 + expandR[i + 3] * 2 + expandR[i + 4];
		int num = S_BOX[i / 6][row][col];
//		int num = S_BOX[0][row][col];
		bitset<4> temp(num);
		output[x + 3] = temp[0];
		output[x + 2] = temp[1];
		output[x + 1] = temp[2];
		output[x] = temp[3];
		x += 4;
	}
	//P盒置换
	bitset<32> tmp = output;
	for (int i = 0; i < 32; i++)
		output[i] = tmp[P[i] - 1];
 
	return output;
}
//左移函数
bitset<28> des::leftshift(bitset<28> k, int shift) {
	bitset<28> temp = k;
	if (shift == 1)
	{
		for (int i = 0; i < 27; i++)
		{
			if (i - shift < 0)
				k[i - shift + 28] = temp[i];
			else
				k[i] = temp[i + shift];
		}
	}
	if (shift == 2)
	{
		for (int i = 0; i < 26; i++)
		{
			if (i - shift < 0)
				k[i - shift + 28] = temp[i];
			else
				k[i] = temp[i + shift];
		}
	}
	return k;
}
 
void des::generateKeys() {
	bitset<56> real_key;
	bitset<28> left;
	bitset<28> right;
	bitset<48> compressKey;
 
	//首先经过选择置换PC-1，将初始密钥的8bit奇偶校验位去掉
	//并重新编排
	for (int i = 0; i < 56; i++)
		real_key[i] = key_[PC_1[i] - 1];
 
	for (int round = 0; round < 16; round++)
	{
		for (int i = 0; i < 28; i++)
			left[i] = real_key[i];
		for (int i = 28; i < 56; i++)
			right[i - 28] = real_key[i];
		//左移
		left = leftshift(left, shiftBits[round]);
		right = leftshift(right, shiftBits[round]);
		//连接，置换选择PC-2做重排，进行压缩
		for (int i=0; i < 28; i++)
			real_key[i] = left[i];
		for (int i = 28; i < 56; i++)
			real_key[i] = right[i - 28];
		for (int i = 0; i < 48; i++)
		{
			int m = PC_2[i];
			compressKey[i] = real_key[m - 1];
		}                                   
		
		subkey_[round] = compressKey;
	}
}

bitset<8> des::char_to_bit8(const char s){
	bitset<8> bits;
	int num = int(s);
	bitset<8> temp(num);
	for (int j = 7; j >= 0; j--) bits[j] = temp[7 - j];
	return bits;
}

// 工具函数：将char字符数组转为二进制
bitset<64> des::char_to_bit(const char s[8]) {
	bitset<64> bits;
	int x = 0;
	for (int i = 0; i < 8; i++)
	{
		int num = int(s[i]);
		bitset<8> temp(num);
		for (int j = 7; j >= 0; j--)
		{
			bits[x + j] = temp[7 - j];
		}
		x += 8;
	}
	return bits;
}
//工具函数：进行二进制逆向转换
bitset<64> des::change(bitset<64> temp) {
	bitset<64> bits;
	bitset<8> n;
	for (int i = 0; i < 64; i = i + 8)
	{
		for (int j = 0; j < 8; j++)
		{
			bits[i + j] = temp[i + 7 - j];
		}
	}
	return bits;
}

bitset<64> des::des_encrypt(bitset<64> &plain) {
	bitset<64> cipher;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	//初始置换IP
	for (int i = 0; i < 64; i++)
		currentBits[i] = plain[IP[i] - 1];//
 
	for (int i = 0; i < 32; i++)
		left[i] = currentBits[i];
	for (int i = 32; i < 64; i++)
		right[i - 32] = currentBits[i];
	//进入16轮轮变换
	for (int round = 0; round < 16; round++)
	{
		newLeft = right;
		right = left ^ F(right, subkey_[round]);
		left = newLeft;
	}
	//合并
	for (int i = 0; i < 32; i++)
		cipher[i] = right[i];
	for (int i = 32; i < 64; i++)
		cipher[i] = left[i - 32];
	//逆初始化置换
	currentBits = cipher;
	for (int i = 0; i < 64; i++)
		cipher[i] = currentBits[IP_1[i] - 1];
 	
	return cipher;
}


bitset<64> des::des_decrypt(bitset<64> & cipher) {
	bitset<64> plain;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	//置换IP
	for (int i = 0; i < 64; i++)
		currentBits[i] = cipher[IP[i] - 1];
 
	for (int i = 0; i < 32; i++)
		left[i] = currentBits[i];
	for (int i = 32; i < 64; i++)
		right[i - 32] = currentBits[i];
	//进入16轮迭代（子密钥逆序应用）
	for (int round = 0; round < 16; round++)
	{
		newLeft = right;
		right = left ^ F(right, subkey_[15 - round]);
		left = newLeft;
	}
	//合并
	for (int i = 0; i < 32; i++)
		plain[i] = right[i];
	for (int i = 32; i < 64; i++)
		plain[i] = left[i - 32];
	//逆初始化置换
	currentBits = plain;
	for (int i = 0; i < 64; i++)
		plain[i] = currentBits[IP_1[i] - 1];
 
	return plain;
}

void des::clearStringBlocks(void){
	if (pStrings!=NULL) delete [] pStrings;
	pStrings = NULL;
	block_num = 0;
}

bool des::cutStringByBlock(string str){
	int len = 0;
	string *strs = new string[str.length() / 8 + 1];
	
	for(int i=0;i<str.length()/8;++i) strs[i] = str.substr(i*8,8);
	if (str.length() % 8){
		strs[str.length()/8] = str.substr((str.length()/8) * 8 );
		for(int i=str.length()% 8 ;i<8;++i) strs[str.length()/8][i] = 0; //padding 0
		len = str.length()/8 + 1;
	}else
		len = str.length()/8;	
		
	if (pStrings != NULL) delete [] pStrings;
	pStrings = strs;
	block_num = len;
}

bool des::gnrSubKeys(string key){
	k_=key;
	key_ = char_to_bit(key.c_str());
	generateKeys();
}

void des::encrypt(string s,string k,bool showCipher=false) {
	gnrSubKeys(k);
	for(int i=s.length() ;i<8;++i) s[i] = 0; //padding 0
	bitset<64> plain = char_to_bit(s.c_str());	
	bitset<64> cipher = des_encrypt(plain);
	for(int i=0;i<8;++i){
		unsigned char cc = 0;
		for(int j=0;j<8;++j) if (cipher[i*8+j]) cc |= (1<<(7-j));
		if (showCipher) printf("%02x ",cc);
	}
	if (showCipher) cout<<endl;
 	
	fstream file1;
	file1.open("./a.txt", ios::binary | ios::out);
	file1.write((char*)&cipher, sizeof(cipher));
	file1.close();
}
 
void des::decrypt() {
	bitset<64> temp;
	fstream file2;
	file2.open("./a.txt", ios::binary | ios::in);
	file2.read((char*)&temp, sizeof(temp));
	file2.close();
 
	// 加密时将bitset逆序(因为BItset原本是低位在低，如num=2,bitset存为0100 0000) 写出文件的也是逆序。
	// 并且重构了左移右移
	// 因此解码的时候用temp_plain,解码后输出需要再逆序一下(c自带的流输出也是低位先输出 同bitset) 
	bitset<64> temp_plain = des_decrypt(temp);
	bitset<64> temp_1 = change(temp_plain);
	
	string dec;
	cout<<"decrypt:"<<endl;
	for(int i=0;i<8;++i){
		char cc = 0;
		for(int j=0;j<8;++j) if (temp_plain[i*8+j]) cc |= (1<<(7-j)); 
		dec+= cc;
	}
	cout<<dec<<endl<<endl;
 	
	file2.open("./b.txt", ios::binary | ios::out);
	file2.write((char*)&temp_1, sizeof(temp_1));
	file2.close();
}

