/*
 example :ecc
 only support the prime is set to 0~2^31-1 can work,
 note that plain 'm' must meet 'km<=p' ,where 'k' is the search range of embeded x ,'p' is a large prime.
 if group data by 1 byte 0<=m<=255.
 
 ecc: y^2 = x^3 + ax + b mod p
 
 author  :lx
*/

#include "ecc.h"

class ecc{
	public:
		int _a,_b,_p,_k,_na; // _na is private key , _k is search range
		ePoint _G;
		ePoint publicKey;
		
		/*
			k' is the search range of embeded x ,'p' is a large prime, na is private key.
			Gx and Gy is generated unit of ecc.
		*/
		bool init(int64 a,int64 b,int64 p,int64 k=30,int64 na=20 ,int64 Gx=1,int64 Gy=1,int seed=42){
			if (k<=0 || p <2 || na < 1) raise("k<=0 || p <2 || na < 1");
			srand(seed);
			int64 ta=a%p,tb=b%p;
			ta = (ta*a)%p, ta = (ta*a)%p;
			tb = (tb*b)%p;
			if ( 0 == ( (ta*4+27*tb) % p )) raise("4a^3+27b^2 mod p == 0");
			if (!prime(p,6)) raise("p is not a prime");
			
			_a = a,_b=b,_k=k,_p=p,_na=na;			
			_G.a = a, _G.b = b , _G.p = p, _G.x = Gx,_G.y = Gy;
			publicKey = _G*_na;
			return true;			
		}
		
		// [l,r] means the search range of prime.
		bool init(int a,int b,int k=30,int l=10000,int r=100000,int seed=42){
			int pt=-1,t=l;
			srand(seed);
			if (k<=0 ) raise("search range 'k' should be greater than 1");
			while (t <= r){
				if (prime(t,10)) {
					pt = t;
					break;
					}
				++t;
			}
			if (pt == -1) raise("cannot find prime in [l,r]");
			
			int64 ta=a%pt,tb=b%pt;
			ta = (ta*a)%pt,ta = (ta*a)%pt;	
			tb = (tb*b)%pt;
			if ( 0 == ( (ta*4+27*tb) % pt )) raise("4a^3+27b^2 mod p == 0"); 
			
			_a = a,_b=b,_k=k,_p = pt;
			_G.a = a, _G.b = b , _G.p = _p;
			
			ePoint ep = createPoint();
			int64 rnd = Random(1,_p/_k-1) ;
			while (embedPlain(rnd,ep) == false) rnd = Random(1,_p/_k-1);// may fail?
			
			_na = Random(2,100);
			publicKey = ep*_na;
			_G = ep;
			return true;		
		}

		int64 calcX(int64 x){
			int64 x_mod = x % _p;
			int64 x_tmp = x_mod;
			x_tmp = (x_tmp * x_mod) % _p;
			x_tmp = (x_tmp * x_mod) % _p;
			
			x_tmp = (x_tmp + _a*x_mod + _b)%_p;
			return x_tmp;
		}
		
		ePoint createPoint(int64 x=INF,int64 y=INF) { 
			if (_p <= 0) raise("initialize p before createPoint");
			ePoint ep;
			ep.a = _a, ep.b = _b , ep.p = _p;
			return ep.copy(x,y) ;
		}
		
		//group string by 1 byte
		vector<pair<ePoint,ePoint>> encrypt(string str){
			vector<pair<ePoint,ePoint>> ciphers;
			pair<ePoint,ePoint> cipher;
			rep(i,0,str.length()-1){
				int64 val = int64(str[i]);
				// rndk should be large enough to avoid cracking.
				int64 rndk = 386; 
				ePoint p1,pm=_G,p2;
				embedPlain(val,pm);
				
				rndk = Random(10,1000);
				p1 = _G*rndk;
				p2 = publicKey*rndk;
				p2 = pm+p2;
				cipher = make_pair(p1,p2);
				ciphers.push_back(cipher); 
			}
			return ciphers;
		}
		
		string decrypt(vector<pair<ePoint,ePoint>> & ciphers){
			string ret ;
			rep(i,0,ciphers.size()-1){
				ePoint temp = ciphers[i].first*(-_na); //p2 = Pm+kPa , Pm = p2 - na*p1
				ePoint pm = ciphers[i].second + temp;
				int64 m = pm.x /_k;	
				ret += m&0xff;			
			}
			return ret;
		}
		
		vector<pair<ePoint,ePoint>> encrypt2(string str){
			vector<pair<ePoint,ePoint>> ciphers;
			pair<ePoint,ePoint> cipher;
			rep(i,0,str.length()-1){
				int64 val = int64(str[i]);
				// rndk should be large enough to avoid cracking.
				int64 rndk = 386; 
				ePoint p1,pm=createPoint(i,val),p2;
				
				rndk = Random(10,1000);
				p1 = _G*rndk;
				p2 = publicKey*rndk;
				p2.x = p2.x * i % p2.p,p2.y = p2.y * val % p2.p; 
				cipher = make_pair(p1,p2);
				ciphers.push_back(cipher); 
			}
			return ciphers;
		}
		
		string decrypt2(vector<pair<ePoint,ePoint>> & ciphers){
			string ret ;
			rep(i,0,ciphers.size()-1){
				ePoint temp = ciphers[i].first*_na; 
				ePoint pm = ciphers[i].second;
				pm.x = pm.getInverse(temp.x) * pm.x % pm.p;
				pm.y = pm.getInverse(temp.y) * pm.y % pm.p;
				ret += pm.y&0xff;			
			}
			return ret;
		}		
		
		pair<ePoint,ePoint> encrypt_1(int64 val){
			int64 rndk = 386;
			ePoint p1,pm = _G,p2;
			pair<ePoint,ePoint> cipher;
			
			embedPlain(val,pm);			
			
			rndk = Random(10,1000);			
			p1 = _G * rndk;
			p2 = publicKey*rndk;
			p2 = pm+p2;
			cipher = make_pair(p1,p2);	
					
			return cipher;	
		}	
			
		int64 decrypt_1(pair<ePoint,ePoint> cipher){
			ePoint temp = cipher.first*(-_na); //p2 = Pm+kPa , Pm = p2 - na*p1
			ePoint pm = cipher.second + temp;
			int64 m = pm.x /_k;
			return m;
		}
		
		bool embedPlain(int64 m,ePoint & ep){
			int64 mul = m*_k;
			rep(i,0,_k-1){
				int64 x_ret = calcX(mul+i); 
				int y = 0,flag = 0;
				while(y<_p){
					int64 y2 = y*y;
					if ( (y2 - x_ret)%_p == 0 ){ 
						flag = 1;
						break;
					}
					++y;
				}
				if (flag){
					ep.x = mul+i;
					ep.y = y;
					return true;
				}
			}
			return false;
		}
		
		bool primeTest(uint64 N,uint64 a){
			int64 x=1,y,c=N-1; 
			while(c){
				y = (x*x)%N;
				if (y == 1 && x!=N-1 && x !=1) return false;
				a = (a*a)%N;
				if (c & 0x01) x = (x*a)%N;
				c>>=1;	
			}
			return (x == 1);
		}
		bool prime(uint64 N,uint64 prob){
			if (N <=1 || !(N%2)) return false;
			if (N == 2) return true;
			for(int i=0;i<prob;++i) if (!primeTest(N,Random(1,N-1)) ) return false; 
			return true;
		}
};

int main()
{
	ecc enc;
	ePoint G,ep,e2,ep1;
	string ret ;
	pair<ePoint,ePoint> pair_1;
	vector<pair<ePoint,ePoint> > vpair;
	
//	enc.init(-1,188,30,7660,100000,42); // [l,r]
	enc.init(-1,188,7669,30,58,0,376);
	
	rep(i,1,1000){
		vpair = enc.encrypt2("line1.Ohohtest_test\nline2.hwk for fuzhou\nline3.eof input");
		ret = enc.decrypt2(vpair);	
	}


//	enc.init(-1,188,4177,30,58,0,376);
//	vpair = enc.encrypt("line1.Ohohtest_test\nline2.hwk for fuzhou\nline3.eof input");
//
//	cout<<"ecc.points pair"<<endl;
//	rep(i,0,vpair.size() -1){
//		cout<<"("<<vpair[i].first.x<<","<<vpair[i].first.y<<") ";
//		cout<<"("<<vpair[i].second.x<<","<<vpair[i].second.y<<")"<<endl;
//	}
//	string ret ;
//	ret = enc.decrypt(vpair);
//	cout<<ret<<endl; 

	
//	enc.init(-1,188,751,30,58,0,376);
//	pair_1 = enc.encrypt_1(18); 
//	pair_1.first.print();
//	pair_1.second.print();
//	int64 ret_val = enc.decrypt_1(pair_1);
//	cout<<ret_val<<endl; 
	


}
