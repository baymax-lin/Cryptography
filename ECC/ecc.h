/*
 example :ecc
 only support the prime is set to 0~2^31-1 can work,
 note that plain 'm' must meet 'km<=p' ,where 'k' is the search range of embeded x ,'p' is a large prime.
 if group data by 1 byte 0<=m<=255.
 
 ecc: y^2 = x^3 + ax + b mod p
 
 author  :lx
*/

#pragma once
#include <bits/stdc++.h>
using namespace std;
typedef long long int64;
typedef unsigned long long uint64;
using namespace std;
#define rep(a,b,c) for(int a=b;a<=c;++a)
#define INF  ( (1ULL<<63) -1 )
#define Random(low,up) ((int)((1.0 * rand() /RAND_MAX * (up - low) + low)+0.5))
#define raise(s) {cout<<s<<endl; exit(0);}




typedef struct ePoint{
	int64 x,y;
	int64 a,b,p;
	ePoint copy(int64 x0,int64 y0){ePoint temp = *this;temp.x = x0,temp.y =y0;return temp;}
	bool operator == ( struct ePoint ep){return (x == ep.x && y == ep.y);}
	bool operator != ( struct ePoint ep){return (x != ep.x || y != ep.y);}
	ePoint operator -() { return this->copy(x,(p-y)%p); }
	ePoint operator *(int64 ns){
		ePoint Q = *this;
		if (ns <0) Q = -Q , ns=-ns;
		ePoint ret = Q.getInf();
		while(ns){
			if (ns & 1) ret = ret + Q;
			Q = Q + Q;
			ns>>=1;
		}
		return ret;
	}	
	ePoint operator + ( struct ePoint Q){
		ePoint P = *this;
		int64 x3,y3,r;
		if ( false == P.check(Q)  ) raise("ecc parames are not matched in operator '+'") ;
		if ( P == -Q ) return Q.getInf();
		if ( P.isInf() ) return Q;
		if ( Q.isInf() ) return P;
		if ( P != Q){
			//d_x = 0 and d_y != 0 is impossible,while d_y = 0 and d_x != 0 is possible
			int64 deltaY = y - Q.y;
			int64 deltaX = x - Q.x;
			r = deltaX? (deltaY * getInverse(deltaX)) % p : 0;
		}
		else{
			int64 temp1 = (3*x)%p;
			temp1 = (temp1 * x + a) % p;
			int64 temp2 = (2*y);
			int64 inv = getInverse(temp2);
			r = (inv * temp1) % p;
		}
		if (r < 0) r += p;
		
		x3 = (r*r) % p;
		x3 = (x3 - x - Q.x)% p;
		if (x3 < 0) x3 += p;
		
		y3 = (r*(x - x3)-y) % p;
		if (y3 < 0) y3 += p;
	
		P.x = x3,P.y = y3;
		return P ;
	}
	inline int64 gcd(int64 aa, int64 bb){
		return (bb == 0)? aa : gcd(bb, aa%bb);
	}		
	void eGcd(int64 aa, int64 bb,int64 &xx,int64&yy,int64&dd){
		if(bb == 0) xx = 1,yy = 0,dd = aa;
		else{
			eGcd(bb, aa%bb,xx,yy,dd);
			uint64 temp = xx;
			xx = yy;
			yy = temp - aa/bb*yy;
		}
	}
	int64 getInverse(int64 e){
		e = (e%p+p)%p; // if e<0 and p is a prime ,then gcd(e,d) will be -1,so make sure e is positive.
		if (gcd(e,p) != 1) raise("gcd(e,p) is not equal to 1");
		int64 x0,y0,d;
		eGcd(e,p,x0,y0,d);
		x0 = x0 + p;
		x0 = (x0%p + p)%p; //transfered to minimum positive solution
		return x0;
	}	
	ePoint getInf(void) { return this->copy(INF,INF); }
	bool isInf(void){ return (this->x == INF || this->y == INF) ;}
	bool check(const struct ePoint &ep){ return (this->p == ep.p && this->a == ep.a && this->b == ep.b);}
	void print(void){
		if (this->isInf() ) cout<<"inf inf"<<endl;
		else cout<<x<<" "<<y<<endl;	
	}
}ePoint;



