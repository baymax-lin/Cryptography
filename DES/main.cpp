#include<iostream>
#include<string>
#include<ctime>
#include"base.h"
#include "mode.h"
using namespace std;

/*
 example :des base and expansion (ecb cbc cfb ofb)
 author :lx
*/
bitset<64> change64 (bitset<64> temp) {
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

bitset<8> change8 (bitset<8> temp) {
	bitset<8> bits;

	for (int j = 0; j < 8; j++)
	{
		bits[j] = temp[7 - j];
	}
	return bits;
}

void showCipher(vector<bitset<64>> &cipher){
	cout<<"cipher:"<<endl;
	unsigned int l1,l2;

	for(int i=0;i<cipher.size();++i){
		l1 = l2 = 0;
		for(int j=0;j<32;++j) l1 |= (cipher[i][63-j] << (31-j));
		for(int j=0;j<32;++j) l2 |= (cipher[i][31-j] << (31-j));
		printf("%02x %02x ",l1,l2);
	}
	cout<<endl<<endl;;
}

void showCipher_8(vector<bitset<8>> &cipher){
	cout<<"cipher:"<<endl;
	for(int i=0;i<cipher.size();++i){
		bitset<8> temp = change8(cipher[i]);
		printf("%02x ",temp.to_ulong());
	}
	cout<<endl<<endl;;
}

// des dec/enc r = l xor f-fun can be proved that it is symmetrical and it is not related to S-box.
// func 'change' is not a good solution, it's best to match the left-shift of des_base. be lazy to modify.
int main() {
	des enc0;
	ecb enc1;
	cbc enc2;
	cfb enc3;
	ofb enc4;
	string s = "line1.Ohohtest_test\nline2.hwk for fuzhou\nline3.eof input";
	string k = "12345675";
	string k2 = "12345679";
	vector<bitset<64>> cipher  ;
	vector<bitset<8>> cipher8  ;
	string ret ;

	cout<<"base mode(Lowest 8 bytes):"<<endl;
	enc0.encrypt(s,k,true);
	enc0.decrypt();
	
	cout<<"ecb mode:"<<endl;
	enc1.encryptByDES(s,k,cipher) ;
	showCipher(cipher);
	enc1.decryptByDES(cipher,k,ret);
	cout<<"decrypt:"<<endl<<ret<<endl<<endl;
	
	cout<<"cbc mode:"<<endl;
	enc2.encryptByDES(s,k,cipher) ;
	showCipher(cipher);
	enc2.decryptByDES(cipher,k,ret);
	cout<<"decrypt:"<<endl<<ret<<endl<<endl;
	
	cout<<"cfb mode:"<<endl;
	enc3.encryptByDES(s,k,cipher) ;
	showCipher(cipher);
	enc3.decryptByDES(cipher,k,ret);
	cout<<"decrypt:"<<endl<<ret<<endl<<endl;
	
	cout<<"ofb mode:"<<endl;
	enc4.encryptByDES(s,k,cipher) ;
	showCipher(cipher);
	enc4.decryptByDES(cipher,k,ret);
	cout<<"decrypt:"<<endl<<ret<<endl<<endl;
	
	cout<<"ofb mode(using streaming mode):"<<endl;
	enc4.encryptByStreamingDES(s,k,cipher8);
	showCipher_8(cipher8);
	enc4.decryptByStreamingDES(cipher8,k,ret);  
	cout<<"decrypt:"<<endl<<ret<<endl<<endl;
 	
	return 0;
}


