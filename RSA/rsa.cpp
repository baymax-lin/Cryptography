#include <bits/stdc++.h>
using namespace std;
typedef long long int64;
typedef unsigned long long uint64;
using namespace std;

#define throw(s) {cout<<s<<endl; exit(0);}
#define Random(low,up) ((int)((1.0 * rand() /RAND_MAX * (up - low) + low)+0.5))

/*
 example :rsa (small number)
 support only prime is set to 0~2^31-1 can work,
 otherwise the large number multiplication is required. 
 author :lx
*/
class rsa{
	public:

		int64 p,q,n,e,d,seg; // p q are prime 
		
		bool init(int l ,int r,int seed,int seglen){
			int t = l,cnt = 0,tSeg;
			int64 p0[2];
			p0[0] = p0[1] = -1;
			srand(seed);
			while (t <= r){
				int rnd = Random(1,100);
				if (rnd < 100) if (prime(t,6)) {
					p0[cnt++] = t;
					if (cnt == 2) break;
				}
				++t;
			}
			if (seglen&(seglen-1) || seglen >4 || !seglen){
				cout<<"illegal segment length."<<endl;
				return false;
			}
			
			if (p0[0]== -1 || p0[1] == -1) {
				cout<<"cannot find prime. Expand the range of 'l' and 'r' to find more."<<endl;
				return false;
			}
			p = p0[0];
			q = p0[1];
			n = p*q;
			int64 dd ,nn,x,y;
			int64 fi_n = (p-1)*(q-1);
			
			// we need to select a e ramdomly , which belongs to [1,fi_n] and gcd(e,fi_n) = 1
			e = Random(1,fi_n); 
			while (this->gcd(e,fi_n) !=1 ) e = Random(1,fi_n); 
			
			eGcd(e,fi_n,x,y,dd); // note :ed-np = 1 ,np may be overflow . gcd = dd = 1
			// general solution: x = x0 + kb/d , y = y0 - ka/d (d=gcd kb=b,ka=a). here d = 1 , b/d = n
			x = x + fi_n;
			x = (x%fi_n + fi_n)%fi_n; //transfered to minimum positive solution
			d = x;
			
			if (n < (1ULL << 8*seglen)){
				cout<<"'n' must greater than the upper of int(str.grp(i)). "\
				"Expand the range of 'l' and 'r' to match"<<endl;
				return false;				
			}
			seg = seglen;
			return true;		
		}
		vector<int> encrypt(string plain){
			vector<int> cipher;
			int cnt= 0;
			int value = 0;
			for(int i=0;i<plain.length() ;++i){
				if (cnt == 0) value = 0;
				value |= ((char)plain[i]) << ( (seg-1-cnt)*8 ) ;
				cnt++;
				if (cnt == seg){
					cipher.push_back(this->fastPower(value,e,n)) ; 
					value = cnt = 0;
				}
			} 
			if (value) cipher.push_back(this->fastPower(value,e,n)); // clear the tail
			return cipher;
		}
		
		void showCipher(vector<int> cipher){
			cout<<"cipher"<<endl;
			for(int i=0;i<cipher.size();++i)
				printf("%02x ",cipher[i]);
			cout<<endl<<endl;;
		}
		string decrypt(vector<int> cipher){
			string plain;
			for(int i=0;i<cipher.size();++i){				
				int dec = this->fastPower(cipher[i],d,n);
				for(int j=seg-1;j>=0;--j){
					char tc = 0xff & (dec >> (j*8));
					plain +=tc;
				}
			}
			return plain;			
		}
		int64 fastPower(int64 a,int64 b,int64 n){
			int64 c = 1;
			int i=63;
			while (i){
				if (b & (1LL<<i)) c = (c*a)%n ;
				c = (c*c)%n;
				i--;
			}
			if (b & 1) c = (c*a)%n;
			return c;
		}
		
	private:
		inline int64 gcd(int64 a, int64 b){
			return (b == 0)? a : gcd(b, a%b);
		}		
		void eGcd(int64 a, int64 b,int64 &x,int64&y,int64&d){
			if(b == 0){
				x = 1,y = 0,d = a; //when b=0,ax+by=a*1+b*0 = a = gcd(org_p,org_q)=1
			}
			else{
				eGcd(b, a%b,x,y,d);
				uint64 temp = x;
				x = y;
				y = temp - a/b*y;
			}
		}
		bool primeTest(uint64 N,uint64 a){
			int64 x=1,y,c=N-1; //N-1 must be even so it can be expressed as k*2^s (k=1 here)
			while(c){
				y = (x*x)%N;
				if (y == 1 && x!=N-1 && x !=1) return false;
				a = (a*a)%N;
				if (c &0x01) x = (x*a)%N;
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
int main(){
	rsa r;
	if (r.init(555,1000,42,1)){
		vector<int> cipher = r.encrypt("line1.Ohohtest_test\nline2.hwk for fuzhou\nline3.eof input");
		r.showCipher(cipher);
		string plain = r.decrypt(cipher); 
		cout<<"plainText:"<<endl;
		cout<<plain<<endl;		
	} 
}
