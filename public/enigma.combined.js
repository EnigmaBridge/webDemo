"use strict";function q(a){throw a;}var t=void 0,u=!1;var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};
"undefined"!=typeof module&&module.exports&&(module.exports=sjcl);
sjcl.cipher.aes=function(a){this.j[0][0][0]||this.D();var b,c,d,e,f=this.j[0][4],g=this.j[1];b=a.length;var h=1;4!==b&&(6!==b&&8!==b)&&q(new sjcl.exception.invalid("invalid aes key size"));this.a=[d=a.slice(0),e=[]];for(a=b;a<4*b+28;a++){c=d[a-1];if(0===a%b||8===b&&4===a%b)c=f[c>>>24]<<24^f[c>>16&255]<<16^f[c>>8&255]<<8^f[c&255],0===a%b&&(c=c<<8^c>>>24^h<<24,h=h<<1^283*(h>>7));d[a]=d[a-b]^c}for(b=0;a;b++,a--)c=d[b&3?a:a-4],e[b]=4>=a||4>b?c:g[0][f[c>>>24]]^g[1][f[c>>16&255]]^g[2][f[c>>8&255]]^g[3][f[c&
255]]};
sjcl.cipher.aes.prototype={encrypt:function(a){return y(this,a,0)},decrypt:function(a){return y(this,a,1)},j:[[[],[],[],[],[]],[[],[],[],[],[]]],D:function(){var a=this.j[0],b=this.j[1],c=a[4],d=b[4],e,f,g,h=[],l=[],k,n,m,p;for(e=0;0x100>e;e++)l[(h[e]=e<<1^283*(e>>7))^e]=e;for(f=g=0;!c[f];f^=k||1,g=l[g]||1){m=g^g<<1^g<<2^g<<3^g<<4;m=m>>8^m&255^99;c[f]=m;d[m]=f;n=h[e=h[k=h[f]]];p=0x1010101*n^0x10001*e^0x101*k^0x1010100*f;n=0x101*h[m]^0x1010100*m;for(e=0;4>e;e++)a[e][f]=n=n<<24^n>>>8,b[e][m]=p=p<<24^p>>>8}for(e=
0;5>e;e++)a[e]=a[e].slice(0),b[e]=b[e].slice(0)}};
function y(a,b,c){4!==b.length&&q(new sjcl.exception.invalid("invalid aes block size"));var d=a.a[c],e=b[0]^d[0],f=b[c?3:1]^d[1],g=b[2]^d[2];b=b[c?1:3]^d[3];var h,l,k,n=d.length/4-2,m,p=4,s=[0,0,0,0];h=a.j[c];a=h[0];var r=h[1],v=h[2],w=h[3],x=h[4];for(m=0;m<n;m++)h=a[e>>>24]^r[f>>16&255]^v[g>>8&255]^w[b&255]^d[p],l=a[f>>>24]^r[g>>16&255]^v[b>>8&255]^w[e&255]^d[p+1],k=a[g>>>24]^r[b>>16&255]^v[e>>8&255]^w[f&255]^d[p+2],b=a[b>>>24]^r[e>>16&255]^v[f>>8&255]^w[g&255]^d[p+3],p+=4,e=h,f=l,g=k;for(m=0;4>
m;m++)s[c?3&-m:m]=x[e>>>24]<<24^x[f>>16&255]<<16^x[g>>8&255]<<8^x[b&255]^d[p++],h=e,e=f,f=g,g=b,b=h;return s}
sjcl.bitArray={bitSlice:function(a,b,c){a=sjcl.bitArray.O(a.slice(b/32),32-(b&31)).slice(1);return c===t?a:sjcl.bitArray.clamp(a,c-b)},extract:function(a,b,c){var d=Math.floor(-b-c&31);return((b+c-1^b)&-32?a[b/32|0]<<32-d^a[b/32+1|0]>>>d:a[b/32|0]>>>d)&(1<<c)-1},concat:function(a,b){if(0===a.length||0===b.length)return a.concat(b);var c=a[a.length-1],d=sjcl.bitArray.getPartial(c);return 32===d?a.concat(b):sjcl.bitArray.O(b,d,c|0,a.slice(0,a.length-1))},bitLength:function(a){var b=a.length;return 0===
b?0:32*(b-1)+sjcl.bitArray.getPartial(a[b-1])},clamp:function(a,b){if(32*a.length<b)return a;a=a.slice(0,Math.ceil(b/32));var c=a.length;b&=31;0<c&&b&&(a[c-1]=sjcl.bitArray.partial(b,a[c-1]&2147483648>>b-1,1));return a},partial:function(a,b,c){return 32===a?b:(c?b|0:b<<32-a)+0x10000000000*a},getPartial:function(a){return Math.round(a/0x10000000000)||32},equal:function(a,b){if(sjcl.bitArray.bitLength(a)!==sjcl.bitArray.bitLength(b))return u;var c=0,d;for(d=0;d<a.length;d++)c|=a[d]^b[d];return 0===
c},O:function(a,b,c,d){var e;e=0;for(d===t&&(d=[]);32<=b;b-=32)d.push(c),c=0;if(0===b)return d.concat(a);for(e=0;e<a.length;e++)d.push(c|a[e]>>>b),c=a[e]<<32-b;e=a.length?a[a.length-1]:0;a=sjcl.bitArray.getPartial(e);d.push(sjcl.bitArray.partial(b+a&31,32<b+a?c:d.pop(),1));return d},k:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};
sjcl.codec.utf8String={fromBits:function(a){var b="",c=sjcl.bitArray.bitLength(a),d,e;for(d=0;d<c/8;d++)0===(d&3)&&(e=a[d/4]),b+=String.fromCharCode(e>>>24),e<<=8;return decodeURIComponent(escape(b))},toBits:function(a){a=unescape(encodeURIComponent(a));var b=[],c,d=0;for(c=0;c<a.length;c++)d=d<<8|a.charCodeAt(c),3===(c&3)&&(b.push(d),d=0);c&3&&b.push(sjcl.bitArray.partial(8*(c&3),d));return b}};
sjcl.codec.hex={fromBits:function(a){var b="",c;for(c=0;c<a.length;c++)b+=((a[c]|0)+0xf00000000000).toString(16).substr(4);return b.substr(0,sjcl.bitArray.bitLength(a)/4)},toBits:function(a){var b,c=[],d;a=a.replace(/\s|0x/g,"");d=a.length;a+="00000000";for(b=0;b<a.length;b+=8)c.push(parseInt(a.substr(b,8),16)^0);return sjcl.bitArray.clamp(c,4*d)}};
sjcl.codec.base64={I:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",fromBits:function(a,b,c){var d="",e=0,f=sjcl.codec.base64.I,g=0,h=sjcl.bitArray.bitLength(a);c&&(f=f.substr(0,62)+"-_");for(c=0;6*d.length<h;)d+=f.charAt((g^a[c]>>>e)>>>26),6>e?(g=a[c]<<6-e,e+=26,c++):(g<<=6,e-=6);for(;d.length&3&&!b;)d+="=";return d},toBits:function(a,b){a=a.replace(/\s|=/g,"");var c=[],d,e=0,f=sjcl.codec.base64.I,g=0,h;b&&(f=f.substr(0,62)+"-_");for(d=0;d<a.length;d++)h=f.indexOf(a.charAt(d)),
0>h&&q(new sjcl.exception.invalid("this isn't base64!")),26<e?(e-=26,c.push(g^h>>>e),g=h<<32-e):(e+=6,g^=h<<32-e);e&56&&c.push(sjcl.bitArray.partial(e&56,g,1));return c}};sjcl.codec.base64url={fromBits:function(a){return sjcl.codec.base64.fromBits(a,1,1)},toBits:function(a){return sjcl.codec.base64.toBits(a,1)}};sjcl.hash.sha256=function(a){this.a[0]||this.D();a?(this.q=a.q.slice(0),this.m=a.m.slice(0),this.g=a.g):this.reset()};sjcl.hash.sha256.hash=function(a){return(new sjcl.hash.sha256).update(a).finalize()};
sjcl.hash.sha256.prototype={blockSize:512,reset:function(){this.q=this.M.slice(0);this.m=[];this.g=0;return this},update:function(a){"string"===typeof a&&(a=sjcl.codec.utf8String.toBits(a));var b,c=this.m=sjcl.bitArray.concat(this.m,a);b=this.g;a=this.g=b+sjcl.bitArray.bitLength(a);for(b=512+b&-512;b<=a;b+=512)z(this,c.splice(0,16));return this},finalize:function(){var a,b=this.m,c=this.q,b=sjcl.bitArray.concat(b,[sjcl.bitArray.partial(1,1)]);for(a=b.length+2;a&15;a++)b.push(0);b.push(Math.floor(this.g/
4294967296));for(b.push(this.g|0);b.length;)z(this,b.splice(0,16));this.reset();return c},M:[],a:[],D:function(){function a(a){return 0x100000000*(a-Math.floor(a))|0}var b=0,c=2,d;a:for(;64>b;c++){for(d=2;d*d<=c;d++)if(0===c%d)continue a;8>b&&(this.M[b]=a(Math.pow(c,0.5)));this.a[b]=a(Math.pow(c,1/3));b++}}};
function z(a,b){var c,d,e,f=b.slice(0),g=a.q,h=a.a,l=g[0],k=g[1],n=g[2],m=g[3],p=g[4],s=g[5],r=g[6],v=g[7];for(c=0;64>c;c++)16>c?d=f[c]:(d=f[c+1&15],e=f[c+14&15],d=f[c&15]=(d>>>7^d>>>18^d>>>3^d<<25^d<<14)+(e>>>17^e>>>19^e>>>10^e<<15^e<<13)+f[c&15]+f[c+9&15]|0),d=d+v+(p>>>6^p>>>11^p>>>25^p<<26^p<<21^p<<7)+(r^p&(s^r))+h[c],v=r,r=s,s=p,p=m+d|0,m=n,n=k,k=l,l=d+(k&n^m&(k^n))+(k>>>2^k>>>13^k>>>22^k<<30^k<<19^k<<10)|0;g[0]=g[0]+l|0;g[1]=g[1]+k|0;g[2]=g[2]+n|0;g[3]=g[3]+m|0;g[4]=g[4]+p|0;g[5]=g[5]+s|0;g[6]=
g[6]+r|0;g[7]=g[7]+v|0}
sjcl.mode.ccm={name:"ccm",encrypt:function(a,b,c,d,e){var f,g=b.slice(0),h=sjcl.bitArray,l=h.bitLength(c)/8,k=h.bitLength(g)/8;e=e||64;d=d||[];7>l&&q(new sjcl.exception.invalid("ccm: iv must be at least 7 bytes"));for(f=2;4>f&&k>>>8*f;f++);f<15-l&&(f=15-l);c=h.clamp(c,8*(15-f));b=sjcl.mode.ccm.K(a,b,c,d,e,f);g=sjcl.mode.ccm.n(a,g,c,b,e,f);return h.concat(g.data,g.tag)},decrypt:function(a,b,c,d,e){e=e||64;d=d||[];var f=sjcl.bitArray,g=f.bitLength(c)/8,h=f.bitLength(b),l=f.clamp(b,h-e),k=f.bitSlice(b,
h-e),h=(h-e)/8;7>g&&q(new sjcl.exception.invalid("ccm: iv must be at least 7 bytes"));for(b=2;4>b&&h>>>8*b;b++);b<15-g&&(b=15-g);c=f.clamp(c,8*(15-b));l=sjcl.mode.ccm.n(a,l,c,k,e,b);a=sjcl.mode.ccm.K(a,l.data,c,d,e,b);f.equal(l.tag,a)||q(new sjcl.exception.corrupt("ccm: tag doesn't match"));return l.data},K:function(a,b,c,d,e,f){var g=[],h=sjcl.bitArray,l=h.k;e/=8;(e%2||4>e||16<e)&&q(new sjcl.exception.invalid("ccm: invalid tag length"));(0xffffffff<d.length||0xffffffff<b.length)&&q(new sjcl.exception.bug("ccm: can't deal with 4GiB or more data"));
f=[h.partial(8,(d.length?64:0)|e-2<<2|f-1)];f=h.concat(f,c);f[3]|=h.bitLength(b)/8;f=a.encrypt(f);if(d.length){c=h.bitLength(d)/8;65279>=c?g=[h.partial(16,c)]:0xffffffff>=c&&(g=h.concat([h.partial(16,65534)],[c]));g=h.concat(g,d);for(d=0;d<g.length;d+=4)f=a.encrypt(l(f,g.slice(d,d+4).concat([0,0,0])))}for(d=0;d<b.length;d+=4)f=a.encrypt(l(f,b.slice(d,d+4).concat([0,0,0])));return h.clamp(f,8*e)},n:function(a,b,c,d,e,f){var g,h=sjcl.bitArray;g=h.k;var l=b.length,k=h.bitLength(b);c=h.concat([h.partial(8,
f-1)],c).concat([0,0,0]).slice(0,4);d=h.bitSlice(g(d,a.encrypt(c)),0,e);if(!l)return{tag:d,data:[]};for(g=0;g<l;g+=4)c[3]++,e=a.encrypt(c),b[g]^=e[0],b[g+1]^=e[1],b[g+2]^=e[2],b[g+3]^=e[3];return{tag:d,data:h.clamp(b,k)}}};
sjcl.mode.ocb2={name:"ocb2",encrypt:function(a,b,c,d,e,f){128!==sjcl.bitArray.bitLength(c)&&q(new sjcl.exception.invalid("ocb iv must be 128 bits"));var g,h=sjcl.mode.ocb2.G,l=sjcl.bitArray,k=l.k,n=[0,0,0,0];c=h(a.encrypt(c));var m,p=[];d=d||[];e=e||64;for(g=0;g+4<b.length;g+=4)m=b.slice(g,g+4),n=k(n,m),p=p.concat(k(c,a.encrypt(k(c,m)))),c=h(c);m=b.slice(g);b=l.bitLength(m);g=a.encrypt(k(c,[0,0,0,b]));m=l.clamp(k(m.concat([0,0,0]),g),b);n=k(n,k(m.concat([0,0,0]),g));n=a.encrypt(k(n,k(c,h(c))));d.length&&
(n=k(n,f?d:sjcl.mode.ocb2.pmac(a,d)));return p.concat(l.concat(m,l.clamp(n,e)))},decrypt:function(a,b,c,d,e,f){128!==sjcl.bitArray.bitLength(c)&&q(new sjcl.exception.invalid("ocb iv must be 128 bits"));e=e||64;var g=sjcl.mode.ocb2.G,h=sjcl.bitArray,l=h.k,k=[0,0,0,0],n=g(a.encrypt(c)),m,p,s=sjcl.bitArray.bitLength(b)-e,r=[];d=d||[];for(c=0;c+4<s/32;c+=4)m=l(n,a.decrypt(l(n,b.slice(c,c+4)))),k=l(k,m),r=r.concat(m),n=g(n);p=s-32*c;m=a.encrypt(l(n,[0,0,0,p]));m=l(m,h.clamp(b.slice(c),p).concat([0,0,0]));
k=l(k,m);k=a.encrypt(l(k,l(n,g(n))));d.length&&(k=l(k,f?d:sjcl.mode.ocb2.pmac(a,d)));h.equal(h.clamp(k,e),h.bitSlice(b,s))||q(new sjcl.exception.corrupt("ocb: tag doesn't match"));return r.concat(h.clamp(m,p))},pmac:function(a,b){var c,d=sjcl.mode.ocb2.G,e=sjcl.bitArray,f=e.k,g=[0,0,0,0],h=a.encrypt([0,0,0,0]),h=f(h,d(d(h)));for(c=0;c+4<b.length;c+=4)h=d(h),g=f(g,a.encrypt(f(h,b.slice(c,c+4))));c=b.slice(c);128>e.bitLength(c)&&(h=f(h,d(h)),c=e.concat(c,[-2147483648,0,0,0]));g=f(g,c);return a.encrypt(f(d(f(h,
d(h))),g))},G:function(a){return[a[0]<<1^a[1]>>>31,a[1]<<1^a[2]>>>31,a[2]<<1^a[3]>>>31,a[3]<<1^135*(a[0]>>>31)]}};
sjcl.mode.gcm={name:"gcm",encrypt:function(a,b,c,d,e){var f=b.slice(0);b=sjcl.bitArray;d=d||[];a=sjcl.mode.gcm.n(!0,a,f,d,c,e||128);return b.concat(a.data,a.tag)},decrypt:function(a,b,c,d,e){var f=b.slice(0),g=sjcl.bitArray,h=g.bitLength(f);e=e||128;d=d||[];e<=h?(b=g.bitSlice(f,h-e),f=g.bitSlice(f,0,h-e)):(b=f,f=[]);a=sjcl.mode.gcm.n(u,a,f,d,c,e);g.equal(a.tag,b)||q(new sjcl.exception.corrupt("gcm: tag doesn't match"));return a.data},U:function(a,b){var c,d,e,f,g,h=sjcl.bitArray.k;e=[0,0,0,0];f=b.slice(0);
for(c=0;128>c;c++){(d=0!==(a[Math.floor(c/32)]&1<<31-c%32))&&(e=h(e,f));g=0!==(f[3]&1);for(d=3;0<d;d--)f[d]=f[d]>>>1|(f[d-1]&1)<<31;f[0]>>>=1;g&&(f[0]^=-0x1f000000)}return e},f:function(a,b,c){var d,e=c.length;b=b.slice(0);for(d=0;d<e;d+=4)b[0]^=0xffffffff&c[d],b[1]^=0xffffffff&c[d+1],b[2]^=0xffffffff&c[d+2],b[3]^=0xffffffff&c[d+3],b=sjcl.mode.gcm.U(b,a);return b},n:function(a,b,c,d,e,f){var g,h,l,k,n,m,p,s,r=sjcl.bitArray;m=c.length;p=r.bitLength(c);s=r.bitLength(d);h=r.bitLength(e);g=b.encrypt([0,
0,0,0]);96===h?(e=e.slice(0),e=r.concat(e,[1])):(e=sjcl.mode.gcm.f(g,[0,0,0,0],e),e=sjcl.mode.gcm.f(g,e,[0,0,Math.floor(h/0x100000000),h&0xffffffff]));h=sjcl.mode.gcm.f(g,[0,0,0,0],d);n=e.slice(0);d=h.slice(0);a||(d=sjcl.mode.gcm.f(g,h,c));for(k=0;k<m;k+=4)n[3]++,l=b.encrypt(n),c[k]^=l[0],c[k+1]^=l[1],c[k+2]^=l[2],c[k+3]^=l[3];c=r.clamp(c,p);a&&(d=sjcl.mode.gcm.f(g,h,c));a=[Math.floor(s/0x100000000),s&0xffffffff,Math.floor(p/0x100000000),p&0xffffffff];d=sjcl.mode.gcm.f(g,d,a);l=b.encrypt(e);d[0]^=l[0];
d[1]^=l[1];d[2]^=l[2];d[3]^=l[3];return{tag:r.bitSlice(d,0,f),data:c}}};sjcl.misc.hmac=function(a,b){this.L=b=b||sjcl.hash.sha256;var c=[[],[]],d,e=b.prototype.blockSize/32;this.o=[new b,new b];a.length>e&&(a=b.hash(a));for(d=0;d<e;d++)c[0][d]=a[d]^909522486,c[1][d]=a[d]^1549556828;this.o[0].update(c[0]);this.o[1].update(c[1])};sjcl.misc.hmac.prototype.encrypt=sjcl.misc.hmac.prototype.mac=function(a){a=(new this.L(this.o[0])).update(a).finalize();return(new this.L(this.o[1])).update(a).finalize()};
sjcl.misc.pbkdf2=function(a,b,c,d,e){c=c||1E3;(0>d||0>c)&&q(sjcl.exception.invalid("invalid params to pbkdf2"));"string"===typeof a&&(a=sjcl.codec.utf8String.toBits(a));e=e||sjcl.misc.hmac;a=new e(a);var f,g,h,l,k=[],n=sjcl.bitArray;for(l=1;32*k.length<(d||1);l++){e=f=a.encrypt(n.concat(b,[l]));for(g=1;g<c;g++){f=a.encrypt(f);for(h=0;h<f.length;h++)e[h]^=f[h]}k=k.concat(e)}d&&(k=n.clamp(k,d));return k};
sjcl.prng=function(a){this.b=[new sjcl.hash.sha256];this.h=[0];this.F=0;this.t={};this.C=0;this.J={};this.N=this.c=this.i=this.T=0;this.a=[0,0,0,0,0,0,0,0];this.e=[0,0,0,0];this.A=t;this.B=a;this.p=u;this.z={progress:{},seeded:{}};this.l=this.S=0;this.u=1;this.w=2;this.Q=0x10000;this.H=[0,48,64,96,128,192,0x100,384,512,768,1024];this.R=3E4;this.P=80};
sjcl.prng.prototype={randomWords:function(a,b){var c=[],d;d=this.isReady(b);var e;d===this.l&&q(new sjcl.exception.notReady("generator isn't seeded"));if(d&this.w){d=!(d&this.u);e=[];var f=0,g;this.N=e[0]=(new Date).valueOf()+this.R;for(g=0;16>g;g++)e.push(0x100000000*Math.random()|0);for(g=0;g<this.b.length&&!(e=e.concat(this.b[g].finalize()),f+=this.h[g],this.h[g]=0,!d&&this.F&1<<g);g++);this.F>=1<<this.b.length&&(this.b.push(new sjcl.hash.sha256),this.h.push(0));this.c-=f;f>this.i&&(this.i=f);this.F++;
this.a=sjcl.hash.sha256.hash(this.a.concat(e));this.A=new sjcl.cipher.aes(this.a);for(d=0;4>d&&!(this.e[d]=this.e[d]+1|0,this.e[d]);d++);}for(d=0;d<a;d+=4)0===(d+1)%this.Q&&A(this),e=B(this),c.push(e[0],e[1],e[2],e[3]);A(this);return c.slice(0,a)},setDefaultParanoia:function(a){this.B=a},addEntropy:function(a,b,c){c=c||"user";var d,e,f=(new Date).valueOf(),g=this.t[c],h=this.isReady(),l=0;d=this.J[c];d===t&&(d=this.J[c]=this.T++);g===t&&(g=this.t[c]=0);this.t[c]=(this.t[c]+1)%this.b.length;switch(typeof a){case "number":b===
t&&(b=1);this.b[g].update([d,this.C++,1,b,f,1,a|0]);break;case "object":c=Object.prototype.toString.call(a);if("[object Uint32Array]"===c){e=[];for(c=0;c<a.length;c++)e.push(a[c]);a=e}else{"[object Array]"!==c&&(l=1);for(c=0;c<a.length&&!l;c++)"number"!=typeof a[c]&&(l=1)}if(!l){if(b===t)for(c=b=0;c<a.length;c++)for(e=a[c];0<e;)b++,e>>>=1;this.b[g].update([d,this.C++,2,b,f,a.length].concat(a))}break;case "string":b===t&&(b=a.length);this.b[g].update([d,this.C++,3,b,f,a.length]);this.b[g].update(a);
break;default:l=1}l&&q(new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string"));this.h[g]+=b;this.c+=b;h===this.l&&(this.isReady()!==this.l&&C("seeded",Math.max(this.i,this.c)),C("progress",this.getProgress()))},isReady:function(a){a=this.H[a!==t?a:this.B];return this.i&&this.i>=a?this.h[0]>this.P&&(new Date).valueOf()>this.N?this.w|this.u:this.u:this.c>=a?this.w|this.l:this.l},getProgress:function(a){a=this.H[a?a:this.B];return this.i>=a?1:this.c>a?1:this.c/
a},startCollectors:function(){this.p||(window.addEventListener?(window.addEventListener("load",this.r,u),window.addEventListener("mousemove",this.s,u)):document.attachEvent?(document.attachEvent("onload",this.r),document.attachEvent("onmousemove",this.s)):q(new sjcl.exception.bug("can't attach event")),this.p=!0)},stopCollectors:function(){this.p&&(window.removeEventListener?(window.removeEventListener("load",this.r,u),window.removeEventListener("mousemove",this.s,u)):window.detachEvent&&(window.detachEvent("onload",
this.r),window.detachEvent("onmousemove",this.s)),this.p=u)},addEventListener:function(a,b){this.z[a][this.S++]=b},removeEventListener:function(a,b){var c,d,e=this.z[a],f=[];for(d in e)e.hasOwnProperty(d)&&e[d]===b&&f.push(d);for(c=0;c<f.length;c++)d=f[c],delete e[d]},s:function(a){sjcl.random.addEntropy([a.x||a.clientX||a.offsetX||0,a.y||a.clientY||a.offsetY||0],2,"mouse")},r:function(){sjcl.random.addEntropy((new Date).valueOf(),2,"loadtime")}};
function C(a,b){var c,d=sjcl.random.z[a],e=[];for(c in d)d.hasOwnProperty(c)&&e.push(d[c]);for(c=0;c<e.length;c++)e[c](b)}function A(a){a.a=B(a).concat(B(a));a.A=new sjcl.cipher.aes(a.a)}function B(a){for(var b=0;4>b&&!(a.e[b]=a.e[b]+1|0,a.e[b]);b++);return a.A.encrypt(a.e)}sjcl.random=new sjcl.prng(6);try{var D=new Uint32Array(32);crypto.getRandomValues(D);sjcl.random.addEntropy(D,1024,"crypto['getRandomValues']")}catch(E){}
sjcl.json={defaults:{v:1,iter:1E3,ks:128,ts:64,mode:"ccm",adata:"",cipher:"aes"},encrypt:function(a,b,c,d){c=c||{};d=d||{};var e=sjcl.json,f=e.d({iv:sjcl.random.randomWords(4,0)},e.defaults),g;e.d(f,c);c=f.adata;"string"===typeof f.salt&&(f.salt=sjcl.codec.base64.toBits(f.salt));"string"===typeof f.iv&&(f.iv=sjcl.codec.base64.toBits(f.iv));(!sjcl.mode[f.mode]||!sjcl.cipher[f.cipher]||"string"===typeof a&&100>=f.iter||64!==f.ts&&96!==f.ts&&128!==f.ts||128!==f.ks&&192!==f.ks&&0x100!==f.ks||2>f.iv.length||
4<f.iv.length)&&q(new sjcl.exception.invalid("json encrypt: invalid parameters"));"string"===typeof a&&(g=sjcl.misc.cachedPbkdf2(a,f),a=g.key.slice(0,f.ks/32),f.salt=g.salt);"string"===typeof b&&(b=sjcl.codec.utf8String.toBits(b));"string"===typeof c&&(c=sjcl.codec.utf8String.toBits(c));g=new sjcl.cipher[f.cipher](a);e.d(d,f);d.key=a;f.ct=sjcl.mode[f.mode].encrypt(g,b,f.iv,c,f.ts);return e.encode(f)},decrypt:function(a,b,c,d){c=c||{};d=d||{};var e=sjcl.json;b=e.d(e.d(e.d({},e.defaults),e.decode(b)),
c,!0);var f;c=b.adata;"string"===typeof b.salt&&(b.salt=sjcl.codec.base64.toBits(b.salt));"string"===typeof b.iv&&(b.iv=sjcl.codec.base64.toBits(b.iv));(!sjcl.mode[b.mode]||!sjcl.cipher[b.cipher]||"string"===typeof a&&100>=b.iter||64!==b.ts&&96!==b.ts&&128!==b.ts||128!==b.ks&&192!==b.ks&&0x100!==b.ks||!b.iv||2>b.iv.length||4<b.iv.length)&&q(new sjcl.exception.invalid("json decrypt: invalid parameters"));"string"===typeof a&&(f=sjcl.misc.cachedPbkdf2(a,b),a=f.key.slice(0,b.ks/32),b.salt=f.salt);"string"===
typeof c&&(c=sjcl.codec.utf8String.toBits(c));f=new sjcl.cipher[b.cipher](a);c=sjcl.mode[b.mode].decrypt(f,b.ct,b.iv,c,b.ts);e.d(d,b);d.key=a;return sjcl.codec.utf8String.fromBits(c)},encode:function(a){var b,c="{",d="";for(b in a)if(a.hasOwnProperty(b))switch(b.match(/^[a-z0-9]+$/i)||q(new sjcl.exception.invalid("json encode: invalid property name")),c+=d+'"'+b+'":',d=",",typeof a[b]){case "number":case "boolean":c+=a[b];break;case "string":c+='"'+escape(a[b])+'"';break;case "object":c+='"'+sjcl.codec.base64.fromBits(a[b],
0)+'"';break;default:q(new sjcl.exception.bug("json encode: unsupported type"))}return c+"}"},decode:function(a){a=a.replace(/\s/g,"");a.match(/^\{.*\}$/)||q(new sjcl.exception.invalid("json decode: this isn't json!"));a=a.replace(/^\{|\}$/g,"").split(/,/);var b={},c,d;for(c=0;c<a.length;c++)(d=a[c].match(/^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i))||q(new sjcl.exception.invalid("json decode: this isn't json!")),b[d[2]]=d[3]?parseInt(d[3],10):d[2].match(/^(ct|salt|iv)$/)?
sjcl.codec.base64.toBits(d[4]):unescape(d[4]);return b},d:function(a,b,c){a===t&&(a={});if(b===t)return a;for(var d in b)b.hasOwnProperty(d)&&(c&&(a[d]!==t&&a[d]!==b[d])&&q(new sjcl.exception.invalid("required parameter overridden")),a[d]=b[d]);return a},X:function(a,b){var c={},d;for(d in a)a.hasOwnProperty(d)&&a[d]!==b[d]&&(c[d]=a[d]);return c},W:function(a,b){var c={},d;for(d=0;d<b.length;d++)a[b[d]]!==t&&(c[b[d]]=a[b[d]]);return c}};sjcl.encrypt=sjcl.json.encrypt;sjcl.decrypt=sjcl.json.decrypt;
sjcl.misc.V={};sjcl.misc.cachedPbkdf2=function(a,b){var c=sjcl.misc.V,d;b=b||{};d=b.iter||1E3;c=c[a]=c[a]||{};d=c[d]=c[d]||{firstSalt:b.salt&&b.salt.length?b.salt.slice(0):sjcl.random.randomWords(2,0)};c=b.salt===t?d.firstSalt:b.salt;d[c]=d[c]||sjcl.misc.pbkdf2(a,c,b.iter);return{key:d[c].slice(0),salt:c.slice(0)}};
/**
 * JavaScript printf/sprintf functions.
 *
 * This code is unrestricted: you are free to use it however you like.
 * 
 * The functions should work as expected, performing left or right alignment,
 * truncating strings, outputting numbers with a required precision etc.
 *
 * For complex cases these functions follow the Perl implementations of
 * (s)printf, allowing arguments to be passed out-of-order, and to set
 * precision and output-length from other argument
 *
 * See http://perldoc.perl.org/functions/sprintf.html for more information.
 *
 * Implemented flags:
 *
 * - zero or space-padding (default: space)
 *     sprintf("%4d", 3) ->  "   3"
 *     sprintf("%04d", 3) -> "0003"
 *
 * - left and right-alignment (default: right)
 *     sprintf("%3s", "a") ->  "  a"
 *     sprintf("%-3s", "b") -> "b  "
 *
 * - out of order arguments (good for templates & message formats)
 *     sprintf("Estimate: %2$d units total: %1$.2f total", total, quantity)
 *
 * - binary, octal and hex prefixes (default: none)
 *     sprintf("%b", 13) ->    "1101"
 *     sprintf("%#b", 13) ->   "0b1101"
 *     sprintf("%#06x", 13) -> "0x000d"
 *
 * - positive number prefix (default: none)
 *     sprintf("%d", 3) -> "3"
 *     sprintf("%+d", 3) -> "+3"
 *     sprintf("% d", 3) -> " 3"
 *
 * - min/max width (with truncation); e.g. "%9.3s" and "%-9.3s"
 *     sprintf("%5s", "catfish") ->    "catfish"
 *     sprintf("%.5s", "catfish") ->   "catfi"
 *     sprintf("%5.3s", "catfish") ->  "  cat"
 *     sprintf("%-5.3s", "catfish") -> "cat  "
 *
 * - precision (see note below); e.g. "%.2f"
 *     sprintf("%.3f", 2.1) ->     "2.100"
 *     sprintf("%.3e", 2.1) ->     "2.100e+0"
 *     sprintf("%.3g", 2.1) ->     "2.10"
 *     sprintf("%.3p", 2.1) ->     "2.1"
 *     sprintf("%.3p", '2.100') -> "2.10"
 *
 * Deviations from perl spec:
 * - %n suppresses an argument
 * - %p and %P act like %g, but without over-claiming accuracy:
 *   Compare:
 *     sprintf("%.3g", "2.1") -> "2.10"
 *     sprintf("%.3p", "2.1") -> "2.1"
 *
 * @version 2011.09.23
 * @author Ash Searle
 */
function sprintf() {
    function pad(str, len, chr, leftJustify) {
	var padding = (str.length >= len) ? '' : Array(1 + len - str.length >>> 0).join(chr);
	return leftJustify ? str + padding : padding + str;

    }

    function justify(value, prefix, leftJustify, minWidth, zeroPad) {
	var diff = minWidth - value.length;
	if (diff > 0) {
	    if (leftJustify || !zeroPad) {
		value = pad(value, minWidth, ' ', leftJustify);
	    } else {
		value = value.slice(0, prefix.length) + pad('', diff, '0', true) + value.slice(prefix.length);
	    }
	}
	return value;
    }

    var a = arguments, i = 0, format = a[i++];
    return format.replace(sprintf.regex, function(substring, valueIndex, flags, minWidth, _, precision, type) {
	    if (substring == '%%') return '%';

	    // parse flags
	    var leftJustify = false, positivePrefix = '', zeroPad = false, prefixBaseX = false;
	    for (var j = 0; flags && j < flags.length; j++) switch (flags.charAt(j)) {
		case ' ': positivePrefix = ' '; break;
		case '+': positivePrefix = '+'; break;
		case '-': leftJustify = true; break;
		case '0': zeroPad = true; break;
		case '#': prefixBaseX = true; break;
	    }

	    // parameters may be null, undefined, empty-string or real valued
	    // we want to ignore null, undefined and empty-string values

	    if (!minWidth) {
		minWidth = 0;
	    } else if (minWidth == '*') {
		minWidth = +a[i++];
	    } else if (minWidth.charAt(0) == '*') {
		minWidth = +a[minWidth.slice(1, -1)];
	    } else {
		minWidth = +minWidth;
	    }

	    // Note: undocumented perl feature:
	    if (minWidth < 0) {
		minWidth = -minWidth;
		leftJustify = true;
	    }

	    if (!isFinite(minWidth)) {
		throw new Error('sprintf: (minimum-)width must be finite');
	    }

	    if (precision && precision.charAt(0) == '*') {
		precision = +a[(precision == '*') ? i++ : precision.slice(1, -1)];
		if (precision < 0) {
		    precision = null;
		}
	    }

	    if (precision == null) {
		precision = 'fFeE'.indexOf(type) > -1 ? 6 : (type == 'd') ? 0 : void(0);
	    } else {
		precision = +precision;
	    }

	    // grab value using valueIndex if required?
	    var value = valueIndex ? a[valueIndex.slice(0, -1)] : a[i++];
	    var prefix, base;

	    switch (type) {
		case 'c': value = String.fromCharCode(+value);
		case 's': {
			      // If you'd rather treat nulls as empty-strings, uncomment next line:
			      // if (value == null) return '';

			      value = String(value);
			      if (precision != null) {
				  value = value.slice(0, precision);
			      }
			      prefix = '';
			      break;
			  }
		case 'b': base = 2; break;
		case 'o': base = 8; break;
		case 'u': base = 10; break;
		case 'x': case 'X': base = 16; break;
		case 'i':
		case 'd': {
			      var number = parseInt(+value);
			      if (isNaN(number)) {
				  return '';
			      }
			      prefix = number < 0 ? '-' : positivePrefix;
			      value = prefix + pad(String(Math.abs(number)), precision, '0', false);
			      break;
			  }
		case 'e': case 'E':
		case 'f': case 'F':
		case 'g': case 'G':
		case 'p': case 'P':
		          {
			      var number = +value;
			      if (isNaN(number)) {
				  return '';
			      }
			      prefix = number < 0 ? '-' : positivePrefix;
			      var method;
			      if ('p' != type.toLowerCase()) {
				  method = ['toExponential', 'toFixed', 'toPrecision']['efg'.indexOf(type.toLowerCase())];
			      } else {
				  // Count significant-figures, taking special-care of zeroes ('0' vs '0.00' etc.)
				  var sf = String(value).replace(/[eE].*|[^\d]/g, '');
				  sf = (number ? sf.replace(/^0+/,'') : sf).length;
				  precision = precision ? Math.min(precision, sf) : precision;
				  method = (!precision || precision <= sf) ? 'toPrecision' : 'toExponential';
			      }
			      var number_str = Math.abs(number)[method](precision);
			      // number_str = thousandSeparation ? thousand_separate(number_str): number_str;
			      value = prefix + number_str;
			      break;
			  }
		case 'n': return '';
		default: return substring;
	    }

	    if (base) {
		// cast to non-negative integer:
		var number = value >>> 0;
		prefix = prefixBaseX && base != 10 && number && ['0b', '0', '0x'][base >> 3] || '';
		value = prefix + pad(number.toString(base), precision || 0, '0', false);
	    }
	    var justified = justify(value, prefix, leftJustify, minWidth, zeroPad);
	    return ('EFGPX'.indexOf(type) > -1) ? justified.toUpperCase() : justified;
    });
}
sprintf.regex = /%%|%(\d+\$)?([-+#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegpEGP])/g;

/**
 * Trival printf implementation, probably only useful during page-load.
 * Note: you may as well use "document.write(sprintf(....))" directly
 */
function printf() {
    // delegate the work to sprintf in an IE5 friendly manner:
    var i = 0, a = arguments, args = Array(arguments.length);
    while (i < args.length) args[i] = 'a[' + (i++) + ']';
    document.write(eval('sprintf(' + args + ')'));
}
"use strict";
/**
 * EnigmaBridge API helper functions.
 * @author Dusan Klinec (ph4r05)
 * @license GPL3.
 */

/**
 * Monkey-patching for prototype inheritance.
 *
 * @param parentClassOrObject
 * @param newPrototype
 * @returns {Function}
 */
Function.prototype.inheritsFrom = function( parentClassOrObject, newPrototype ){
    if ( parentClassOrObject.constructor == Function )
    {
        //Normal Inheritance
        this.prototype = new parentClassOrObject;
        this.prototype.constructor = this;
        this.prototype.parent = parentClassOrObject.prototype;

        // Better for calling super methods. Avoids looping.
        this.superclass = parentClassOrObject.prototype;
        this.prototype = $.extend(this.prototype, newPrototype);

        // If we have inheritance chain A->B->C, A = root, A defines method x()
        // B also defines x = function() { this.parent.x.call(this); }, C does not defines x,
        // then calling x on C will cause infinite loop because this references to C in B.x() and this.parent is B in B.x()
        // not A as desired.
    }
    else
    {
        //Pure Virtual Inheritance
        this.prototype = parentClassOrObject;
        this.prototype.constructor = this;
        this.prototype.parent = parentClassOrObject;
        this.superclass = parentClassOrObject;
    }
    return this;
};

/**
 * Base EB package.
 * @type {{name: string}}
 */
var eb = {
    name: "EB",
    /** @namespace Exceptions. */
    exception: {
        /** @constructor Ciphertext is corrupt. */
        corrupt: function (message) {
            this.toString = function () {
                return "CORRUPT: " + this.message;
            };
            this.message = message;
        },
        /** @constructor Invalid input. */
        invalid: function (message) {
            this.toString = function () {
                return "INVALID: " + this.message;
            };
            this.message = message;
        },
    }
};

/**
 * EB misc wrapper.
 * @type {{name: string, genNonce: eb.misc.genNonce, genHexNonce: eb.misc.genHexNonce, genAlphaNonce: eb.misc.genAlphaNonce, xor: eb.misc.xor}}
 */
eb.misc = {
    name: "misc",
    genNonce: function(length, alphabet){
        var nonce = "";
        var alphabetLen = alphabet.length;
        var i = 0;

        for(i = 0; i < length; i++){
            nonce += alphabet.charAt(Math.floor(Math.random() * alphabetLen));
        }

        return nonce;
    },
    genHexNonce: function(length){
        return this.genNonce(length, "0123456789abcdef");
    },
    genAlphaNonce: function (length){
        return this.genNonce(length, "0123456789abcdefghijklmnopqrstuvwxyz");
    },
    xor: function(x,y){
        return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
    },
    absorb: function(dst, src){
        for(var key in src) {
            if (src.hasOwnProperty(key)) {
                dst[key] = src[key];
            }
        }
        return dst;
    }
};

eb.codec = {};

/**
 * Fault tolerant utf8 codec for user entries.
 * When converting from hexcoded string to raw data, data may contain both UTF8 characters and hex-coded characters.
 * Parsing result finds utf8 characters in the hexbytes. If byte sequence does not form valid utf8 character, it is
 * parsed as ordinary hex sequence.
 *
 * When converting from raw data to hexdata, utf8 characters are allowed. Moreover it supports individual byte coding
 * \x[A-Fa-f0-9]{2} and backslash escaping \\. Single individual backslash is ignored.
 * @type {{}}
 */
eb.codec.utf8 = {
    toHex: function(x, options) {
        var i, ln = x.length;
        var out = "";

        for (i = 0; i < ln; i++) {
            var cChar = x.charAt(i);
            var remChars = (ln - i - 1);

            if (cChar === '\\') {
                // Byte coding \xFF ?
                if (remChars >= 3) {
                    var hCode = x.substring(i, i + 4);
                    var hRegex = /\\x([a-fA-F0-9]{2})/g;
                    var match = hRegex.exec(hCode);
                    if (match) {
                        out += match[1];
                        i += 3;
                        continue;
                    }
                }

                // Escaping \\ ?
                if (remChars >= 1) {
                    var nChar = x.substring(i + 1, i + 2);
                    if (nChar === '\\') {
                        out += Number('\\'.charCodeAt(0)).toString(16);
                        i += 1;
                        continue;
                    }
                }

                // Invalid escaping, ignore this backslash.
                continue;
            }

            // Get UTF8 hex representation.
            var cc = unescape(encodeURIComponent(cChar));
            var jj, llen;
            for (jj = 0, llen = cc.length; jj < llen; jj++) {
                var chNum = (Number(cc.charCodeAt(jj))).toString(16);
                if ((chNum.length & 1) == 1) {
                    chNum = "0" + chNum;
                }
                out += chNum;
            }
        }

        return out;
    },

    /**
     * Converts hexcoded string to raw data.
     * @param x
     * @param options
     * @returns {string}
     */
    fromHex: function(x, options) {
        var parsed = eb.codec.utf8.fromHexParse(x, options);
        var str="";
        var cur, i, len;
        for(i=0, len=parsed.parsed.length; i<len; i++){
            cur=parsed.parsed[i];
            str += cur.utf8 ? cur.rep : cur.enc;
        }

        return str;
    },

    /**
     * Parses hex coded string, can accept utf8 characters.
     * @param x
     * @param options,
     *      - if acceptUtf8==false, UTF8 characters are not recognized, each character has 1 byte encoding. Default = true,
     *        thus UTF8 characters are recognized and parsed.
     *      - if acceptOnlyUtf8==true, non-UTF8 characters are skipped, otherwise they are parsed as hexcoded.
     *
     * @returns {{nonUtf8Chars: number, parsed: Array}}
     */
    fromHexParse: function(x, options) {
        var defaults = {
            'acceptUtf8': true,
            'acceptOnlyUtf8': false
        };

        options = $.extend(defaults, options || {});
        var acceptUtf8 = options && options.acceptUtf8;
        var acceptOnlyUtf8 = options && options.acceptOnlyUtf8;

        // Process only even lengths.
        var ln = x.length;
        if ((ln & 1) == 1) {
            ln-=1;
        }

        var nonUtf8Chars = 0;
        var i, cByte, cBits, cStr, cNum;
        var out = [];

        // UTF8 encoding table
        //7 	U+0000	    U+007F	    1	0xxxxxxx
        //11	U+0080	    U+07FF	    2	110xxxxx	10xxxxxx
        //16	U+0800	    U+FFFF	    3	1110xxxx	10xxxxxx	10xxxxxx
        //21	U+10000	    U+1FFFFF	4	11110xxx	10xxxxxx	10xxxxxx	10xxxxxx
        //26	U+200000	U+3FFFFFF	5	111110xx	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
        //31	U+4000000	U+7FFFFFFF	6	1111110x	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
        for(i=0; i<ln; i+=2){
            cByte = (x[i] + x[i+1]).toUpperCase();
            cBits = h.toBits(cByte);
            cNum = sjcl.bitArray.extract(cBits,0,8);

            // 1byte char representation. ASCII.
            if (!acceptUtf8 || (cNum & 0x80) == 0){
                out.push({
                    'b':1,
                    'utf8':true,
                    'hex':cByte,
                    'enc':String.fromCharCode(cNum),
                    'rep':cNum < 32 || cNum >= 127 ? "\\x" + cByte : String.fromCharCode(cNum)});
                continue;
            }

            // Look for utf8 character.
            var remBytes = (ln-i-2)/2;
            var valid = false;
            var j = 0;
            for(j=2; j<=6; j++){
                // Create first UTF8 byte mask signature, j = number of bytes character occupies.
                var signature = (Math.pow(2, j)-1)<<1;
                var byteLow = cNum >> (8-j-1);
                if (signature !== byteLow){
                    continue;
                }

                // Signature matched, check if there is enough number of bytes in the buffer
                if (remBytes < (j-1)){
                    break;
                }

                // Start building \uxxxx representation.
                var utfOut = h.toBits(sprintf("0000%x", cNum & ((1<<(8-j-1))-1) ) );
                var utfOutLen = sjcl.bitArray.bitLength(utfOut);
                if (utfOutLen > (8-j-1)){
                    utfOut = sjcl.bitArray.bitSlice(utfOut, utfOutLen-(8-j-1));
                }

                // Check if each next byte has 10xxxxxx format.
                var k = 0;
                var byteValid = true;
                for(k=0; k<j-1; k++){
                    var nByte = eb.codec.utf8.getByte(x, i+2+2*k);
                    if ((nByte >>> 6) != 2){
                        byteValid = false;
                        break;
                    }

                    var cBitArray = h.toBits(sprintf("0000%x", nByte & ((1<<6)-1) ) );
                    var cBitLen = sjcl.bitArray.bitLength(cBitArray);
                    if (cBitLen >= 7){
                        cBitArray = sjcl.bitArray.bitSlice(cBitArray, cBitLen-6);
                    }

                    utfOut = sjcl.bitArray.concat(utfOut, cBitArray);
                }

                // Successing were not in the 10xxxxxx format.
                if(!byteValid){
                    break;
                }

                // utfOut needs to be left padded with zeros to be correctly interpreted.
                utfOutLen = sjcl.bitArray.bitLength(utfOut);
                if ((utfOutLen & 7) != 0){
                    var toPadLen = 8-(utfOutLen & 7);
                    utfOut = sjcl.bitArray.concat(sjcl.bitArray.bitSlice(h.toBits("00"),0,toPadLen), utfOut);
                }

                valid=true;
                out.push({
                    'b':j,
                    'utf8':true,
                    'hex':cByte + x.substring(i+2, i+2+(j-1)*2),
                    'enc':"\\u" + h.fromBits(utfOut),
                    'rep':String.fromCharCode(parseInt(h.fromBits(utfOut), 16))
                });

                i+=2*(j-1);
                break;
            }

            if (valid || acceptOnlyUtf8){
                continue;
            }

            out.push({
                'b':1,
                'utf8':false,
                'hex':cByte,
                'enc':"\\x" + cByte,
                'rep':"\\x" + cByte});

            nonUtf8Chars+=1;
        }

        return {'nonUtf8Chars':nonUtf8Chars, 'parsed':out};
    },

    getByte: function (str, offset){
        var cByte = str[offset] + str[offset+1];
        var cBits = h.toBits(cByte);
        return sjcl.bitArray.extract(cBits,0,8);
    }
};

/**
 * EB padding schemes wrapper.
 * @type {{name: string}}
 */
eb.padding = {
    name: "padding"
};

/**
 * Padding - identity function.
 * @type {{name: string, pad: eb.padding.empty.pad, unpad: eb.padding.empty.unpad}}
 */
eb.padding.empty = {
    name: "empty",
    pad: function(a, blocklen){
        return a;
    },
    unpad: function(a, blocklen){
        return a;
    }
};

/**
 * PKCS7 padding.
 * @type {{name: string, pad: eb.padding.pkcs7.pad, unpad: eb.padding.pkcs7.unpad}}
 */
eb.padding.pkcs7 = {
    name: "pkcs7",
    pad: function(a, blocklen){
        blocklen = blocklen || 16;
        if (!blocklen || (blocklen & (blocklen - 1))){
            throw new sjcl.exception.corrupt("blocklength has to be power of 2");
        }
        if (blocklen != 16){
            throw new sjcl.exception.corrupt("blocklength different than 16 is not implemented yet");
            // TODO: implement multiple block sizes.
        }

        var bl = sjcl.bitArray.bitLength(a);
        var padLen = (16 - ((bl >> 3) & 15));
        var padFill = padLen * 0x1010101;
        return sjcl.bitArray.concat(a, [padFill, padFill, padFill, padFill]).slice(0, ((bl >> 3) + padLen) >> 2);
    },
    unpad: function(a, blocklen){
        blocklen = blocklen || 16;
        if (!blocklen || (blocklen & (blocklen - 1))){
            throw new sjcl.exception.corrupt("blocklength has to be power of 2");
        }
        if (blocklen != 16){
            throw new sjcl.exception.corrupt("blocklength different than 16 is not implemented yet");
            // TODO: implement multiple block sizes.
        }

        var w = sjcl.bitArray;
        var bl = w.bitLength(a);
        if (bl & 127 || !a.length) {
            throw new sjcl.exception.corrupt("input must be a positive multiple of the block size");
        }

        var bi = a[((bl>>3)>>2) - 1] & 255;
        if (bi == 0 || bi > 16) {
            throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
        }

        var bo = bi * 0x1010101;
        if (!w.equal(w.bitSlice([bo, bo, bo, bo], 0, bi << 3), w.bitSlice(a, (a.length << 5) - (bi << 3), a.length << 5))) {
            throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
        }

        return w.bitSlice(a, 0, (a.length << 5) - (bi << 3));
    }
};

/**
 *  PKCS 1.5 padding for RSA operation.
 *
 *  EB = 00 || BT || PS || 00 || D
 *      .. EB = encryption block
 *      .. 00 prefix so EB is not bigger than modulus.
 *      .. BT = 1B block type {00, 01} for private key operation, {02} for public key operation.
 *      .. PS = padding string. Has length k - 3 - len(D).
 *      if BT == 0, then padding consists of 0x0, but we need to know size of data in order to remove padding unambiguously.
 *      if BT == 1, then padding consists of 0xFF.
 *      if BT == 2, then padding consists of randomly generated bytes, does not contain 0x00 byte.
 *      .. D  = data
 *      [https://tools.ietf.org/html/rfc2313 PKCS#1 1.5]
 *
 * @type {{name: string, unpad: eb.padding.pkcs15.unpad, const: *, char: *}}
 */
eb.padding.pkcs15 = {
    name: "pkcs1.5",
    pad: function(a, blockLength, bt){
        var w = sjcl.bitArray;
        var h = sjcl.codec.hex;
        var bl = w.bitLength(a);
        var blb = bl / 8;
        if (bt === undefined){
            bt = 0;
        }
        if (bl & 7 || !a.length) {
            throw new sjcl.exception.corrupt("input type has to have be byte padded, bl="+bl);
        }

        if (bt != 0 && bt != 1 && bt != 2){
            throw new sjcl.exception.corrupt("invalid BT size");
        }

        if (blb+3 > blockLength){
            throw new sjcl.exception.corrupt("data to pad is too big for the padding block length");
        }

        var psLen = blockLength - 3 - blb;
        var ps = [], i, tmp=0;
        for (i=0; i<psLen; i++) {
            var curByte = 0;
            if (bt == 1){
                curByte = 0xff;
            } else if (bt == 2){
                do {
                    curByte = (sjcl.random.randomWords(1, 10)[0]) & 0xff;
                }while(curByte == 0);
            }

            tmp = tmp << 8 | curByte;
            if ((i&3) === 3) {
                ps.push(tmp);
                tmp = 0;
            }
        }
        if (i&3) {
            ps.push(sjcl.bitArray.partial(8*(i&3), tmp));
        }

        var baBuff = h.toBits("00");
        baBuff = w.concat(baBuff, h.toBits(sprintf("%02x", bt)));
        baBuff = w.concat(baBuff, ps);
        baBuff = w.concat(baBuff, h.toBits("00"));
        return w.concat(baBuff, a);
    },
    unpad: function(a){
        var w = sjcl.bitArray;
        var bl = w.bitLength(a);
        var blb = bl / 8;
        if (bl & 7 || blb < 3 || !a.length) {
            throw new sjcl.exception.corrupt("data size block is invalid");
        }

        // Check the first byte.
        var bOffset = 0;
        var prefixByte = w.extract(a, bOffset, 8);
        if (prefixByte != 0x0){
            throw new sjcl.exception.corrupt("data size block is invalid");
        }

        bOffset += 8;
        var bt = w.extract(a, bOffset, 8);

        // BT can be only from set {0,1,2}.
        if (bt != 0 && bt != 1 && bt != 2){
            throw new sjcl.exception.corrupt("Padding data error, BT is outside of the definition set");
        }

        // Find D in the padded data. Strategy depends on the BT.
        var dataPosStart = -1, i= 0, cur=0;
        if (bt == 0){
            // Scan for first non-null character.
            for(i = 2; i < blb; i++){
                cur = w.extract(a, 8*i, 8);
                if (cur != 0){
                    dataPosStart = i;
                    break;
                }
            }

        } else if (bt == 1){
            // Find 0x0, report failure in 0xff
            var ffCorrect = true;
            for(i = 2; i < blb; i++){
                cur = w.extract(a, 8*i, 8);
                if (cur != 0 && cur != 0xff) {
                    ffCorrect = false;
                }

                if (cur == 0){
                    dataPosStart = i+1;
                    break;
                }
            }

            if (!ffCorrect){
                throw new sjcl.exception.corrupt("Trail of 0xFF in padding contains also unexpected characters");
            }

        } else {
            // bt == 2, find 0x0.
            for(i = 2; i < blb; i++){
                cur = w.extract(a, 8*i, 8);
                if (cur == 0){
                    dataPosStart = i+1;
                    break;
                }
            }
        }

        // If data position is out of scope, return nothing.
        if (dataPosStart < 0 || dataPosStart > blb){
            throw new sjcl.exception.corrupt("Padding could not be parsed, dataStart=" + dataPosStart + ", len="+blb);
        }

        // Check size of the output buffer.
        var dataLen = blb - dataPosStart;
        return w.bitSlice(a, dataPosStart*8);
    }
};

/**
 * Extracts 32bit number from the bitArray.
 * Original extract does not work with blength = 32 as 1<<32 == 1, it returns 0 always.
 *
 * @param a
 * @param bstart
 * @returns {*}
 */
sjcl.bitArray.extract32 = function(a, bstart){
    var x, sh = Math.floor((-bstart-32) & 31);
    if ((bstart + 32 - 1 ^ bstart) & -32) {
        x = (a[bstart/32|0] << (32 - sh)) ^ (a[bstart/32+1|0] >>> sh);
    } else {
        x = a[bstart/32|0] >>> sh;
    }
    return x;
};

/**
 * CBC-MAC with given cipher & padding.
 * @param Cipher
 * @param bs
 * @param padding
 */
sjcl.misc.hmac_cbc = function (Cipher, bs, padding) {
    this._cipher = Cipher;
    this._bs = bs = bs || 16;
    this._padding = padding = padding || eb.padding.empty;
};

/**
 * HMAC with the specified hash function.  Also called encrypt since it's a prf.
 * @param {bitArray|String} data The data to mac.
 */
sjcl.misc.hmac_cbc.prototype.encrypt = sjcl.misc.hmac_cbc.prototype.mac = function (data) {
    var i, w = sjcl.bitArray, bl = w.bitLength(data), bp = 0, output = [], xor = eb.misc.xor;
    var bsb = this._bs << 3;

    data = this._padding.pad(data, this._bs);
    var c = sjcl.codec.hex.toBits('00'.repeat(this._bs));
    for (i = 0; bp + bsb <= bl; i += 4, bp += bsb) {
        c = this._cipher.encrypt(xor(c, data.slice(i, i + 4)));
    }
    return c;
};

/**
 * CBC encryption mode.
 * @type {{name: string, encrypt: sjcl.mode.cbc.encrypt, decrypt: sjcl.mode.cbc.decrypt}}
 */
sjcl.mode.cbc = {
    name: "cbc",
    encrypt: function (a, b, c, d, noPad) {
        if (d && d.length) {
            throw new sjcl.exception.invalid("cbc can't authenticate data");
        }
        if (sjcl.bitArray.bitLength(c) !== 128) {
            throw new sjcl.exception.invalid("cbc iv must be 128 bits");
        }

        var i, w = sjcl.bitArray, bl = w.bitLength(b), bp = 0, output = [], xor = eb.misc.xor;
        if (noPad && (bl & 127) != 0){
            throw new sjcl.exception.invalid("when padding is disabled, plaintext has to be a positive multiple of a block size");
        }
        if ((bl & 7) != 0) {
            throw new sjcl.exception.invalid("pkcs#5 padding only works for multiples of a byte");
        }

        for (i = 0; bp + 128 <= bl; i += 4, bp += 128) {
            c = a.encrypt(xor(c, b.slice(i, i + 4)));
            output.splice(i, 0, c[0], c[1], c[2], c[3]);
        }

        if (!noPad){
            bl = (16 - ((bl >> 3) & 15)) * 0x1010101;
            c = a.encrypt(xor(c, w.concat(b, [bl, bl, bl, bl]).slice(i, i + 4)));
            output.splice(i, 0, c[0], c[1], c[2], c[3]);
        }

        return output;
    },
    decrypt: function (a, b, c, d, noPad) {
        if (d && d.length) {
            throw new sjcl.exception.invalid("cbc can't authenticate data");
        }
        if (sjcl.bitArray.bitLength(c) !== 128) {
            throw new sjcl.exception.invalid("cbc iv must be 128 bits");
        }
        if ((sjcl.bitArray.bitLength(b) & 127) || !b.length) {
            throw new sjcl.exception.corrupt("cbc ciphertext must be a positive multiple of the block size");
        }
        var i, w = sjcl.bitArray, bi, bo, output = [], xor = eb.misc.xor;
        d = d || [];
        for (i = 0; i < b.length; i += 4) {
            bi = b.slice(i, i + 4);
            bo = xor(c, a.decrypt(bi));
            output.splice(i, 0, bo[0], bo[1], bo[2], bo[3]);
            c = bi;
        }
        if (!noPad) {
            bi = output[i - 1] & 255;
            if (bi == 0 || bi > 16) {
                throw new sjcl.exception.corrupt("pkcs#5 padding corrupt"); //TODO: padding oracle?
            }
            bo = bi * 0x1010101;
            if (!w.equal(w.bitSlice([bo, bo, bo, bo], 0, bi << 3), w.bitSlice(output, (output.length << 5) - (bi << 3), output.length << 5))) {
                throw new sjcl.exception.corrupt("pkcs#5 padding corrupt"); //TODO: padding oracle?
            }
            return w.bitSlice(output, 0, (output.length << 5) - (bi << 3));
        } else {
            return output;
        }
    }
};

/**
 * Request builder.
 * @type {{}}
 */
eb.comm = {
    name: "comm",
    demangleNonce: function(nonce){
        var ba = sjcl.bitArray;
        var bl = ba.bitLength(nonce);
        if ((bl&7) != 0){
            throw new sjcl.exception.invalid("nonce has to be aligned to bytes");
        }

        var i, w = sjcl.bitArray, bp = 0, output = [], c;
        for (i = 0; bp + 32 <= bl; i += 1, bp += 32) {
            c = nonce.slice(i, i + 1)[0] - 0x01010101;
            output.splice(i, 0, c);
        }

        if (bp+32 == bl){
            return output;
        }

        var rbl = bl - (bp-32);
        var sub = 0x01010101 & (((1<<rbl)-1)<<(32-rbl));
        c = (nonce.slice(i, i + 1)[0] - sub) >>> rbl;
        output.splice(i, 0, c);
        return sjcl.bitArray.clamp(output, bl);
    }
};

/**
 * Raw EB request builder.
 *
 * Data format before encryption:
 * buff = 0x1f | <UOID-4B> | <freshness-nonce-8B> | userdata
 *
 * Encryption
 * AES-256/CBC/PKCS7, IV = 0x00000000000000000000000000000000
 *
 * MAC
 * AES-256-CBC-MAC.
 *
 * encBlock = enc(buff)
 * result = encBlock || mac(encBlock)
 *
 * output = Packet0| _PLAINAES_ | <plain-data-length-4B> | <plaindata> | hexcode(result)
 *
 * @param nonce
 * @param aesKey
 * @param macKey
 * @param userObjectId
 * @param reqType
 */
eb.comm.processDataRequestBodyBuilder = function(nonce, aesKey, macKey, userObjectId, reqType){
    this.userObjectId = userObjectId || -1;
    this.nonce = nonce || "";
    this.aesKey = aesKey || "";
    this.macKey = macKey || "";
    this.reqType = reqType || "PLAINAES";
};
eb.comm.processDataRequestBodyBuilder.prototype = {
    /**
     * User object ID, integer type.
     * @input
     */
    userObjectId : -1,

    /**
     * AES communication encryption key, hexcoded string.
     * @input
     */
    aesKey: "",

    /**
     * AES MAC communication key, hexcoded string.
     * @input
     */
    macKey: "",

    /**
     * Freshness nonce / IV, hexcoded string.
     * @input
     */
    nonce: "",

    /**
     * Request type. PLAINAES by default.
     * @input
     */
    reqType: "",

    /**
     * If set to true, request body building steps are logged.
     * @input
     */
    debuggingLog: false,

    /**
     * Aux logging function
     * @input
     */
    logger: null,

    genNonce: function(){
        this.nonce = eb.misc.genHexNonce(16);
        return this.nonce;
    },

    /**
     * Builds EB request.
     *
     * @param plainData - bitArray of the plaintext data (will be MAC protected).
     * @param requestData - bitArray with userdata to perform operation on (will be encrypted, MAC protected)
     * @returns request body string.
     */
    build: function(plainData, requestData){
        this.nonce = this.nonce || eb.misc.genHexNonce(16);
        var h = sjcl.codec.hex;
        var ba = sjcl.bitArray;
        var pad = eb.padding.pkcs7;

        // Plain data is empty for now.
        var baPlain = plainData;
        var plainDataLength = ba.bitLength(baPlain)/8;

        // Input data flag
        var baBuff = h.toBits("1f");
        // User Object ID
        baBuff = ba.concat(baBuff, h.toBits(sprintf("%08x", this.userObjectId)));
        // Freshness nonce
        baBuff = ba.concat(baBuff, h.toBits(this.nonce));
        // User data
        baBuff = ba.concat(baBuff, requestData);
        // Add padding.
        baBuff = pad.pad(baBuff);
        this._log("ProcessData input: " + h.fromBits(baBuff) + "; len: " + ba.bitLength(baBuff));

        var aesKeyBits = h.toBits(this.aesKey);
        var macKeyBits = h.toBits(this.macKey);

        var aes = new sjcl.cipher.aes(aesKeyBits);
        var aesMac = new sjcl.cipher.aes(macKeyBits);
        var hmac = new sjcl.misc.hmac_cbc(aesMac, 16, eb.padding.empty);

        // IV is null, nonce in the first block is kind of IV.
        var IV = h.toBits('00'.repeat(16));
        var encryptedData = sjcl.mode.cbc.encrypt(aes, baBuff, IV, [], true);
        this._log("encrypted: " + h.fromBits(encryptedData) + ", len=" + ba.bitLength(encryptedData));

        // include plain data in the MAC if non-empty.
        var hmacData = hmac.mac(encryptedData);
        this._log("hmacData: " + h.fromBits(hmacData));

        // Build the request block.
        var requestBase = sprintf("Packet0_%s_%04X%s%s%s",
            this.reqType,
            plainDataLength,
            h.fromBits(plainData),
            h.fromBits(encryptedData),
            h.fromBits(hmacData)
        );

        this._log("request: " + requestBase);
        return requestBase;
    },

    _log:  function(x) {
        if (!this.debuggingLog){
            return;
        }

        if (console && console.log){
            console.log(x);
        }

        if (this.logger){
            this.logger(x);
        }
    }
};

/**
 * Base class for parsed raw EB response.
 */
eb.comm.response = function(){

};
eb.comm.response.prototype = {
    /**
     * Parsed status code. 0x9000 = OK.
     * @output
     */
    statusCode: 0,

    /**
     * Parsed status detail.
     * @output
     */
    statusDetail: "",

    /**
     * Function name extracted from the request.
     */
    function: "",

    /**
     * Raw result of the call.
     * Usually processed by child classes.
     */
    result: "",

    /**
     * Returns true if after parsing, code is OK.
     * @returns {boolean}
     */
    isCodeOk: function(){
        return this.statusCode == 0x9000;
    },

    toString: function(){
        return sprintf("Response{statusCode=0x%4X, statusDetail=[%s], userObjectId: 0x%08X, function: [%s], result: [%s]}",
            this.statusCode,
            this.statusDetail,
            this.userObjectID,
            this.function,
            JSON.stringify(this.result)
        );
    }
};

/**
 * Process data response.
 * Parsed from processData EB response.
 * @extends eb.comm.response
 */
eb.comm.processDataResponse = function(){

};
eb.comm.processDataResponse.inheritsFrom(eb.comm.response, {
    /**
     * Plain data parsed from the response.
     * Nor MACed neither encrypted.
     * @output
     */
    plainData: "",

    /**
     * Protected data parsed from the response.
     * Protected by MAC, encrypted in transit.
     * @output
     */
    protectedData: "",

    /**
     * USerObjectID parsed from the response.
     * Ingeter, 4B.
     */
    userObjectID: 0,

    /**
     * Nonce parsed from the RAW response.
     */
    nonce: "",

    /**
     * MAC value parsed from the message.
     * If macOk is true, it is same as computed MAC.
     */
    mac: "",

    /**
     * Computed MAC value for the message.
     */
    computedMac: "",

    /**
     * Returns true if MAC verification is OK.
     */
    isMacOk: function(){
        var ba = sjcl.bitArray;
        return this.mac
            && this.computedMac
            && ba.bitLength(this.mac) == 16*8
            && ba.bitLength(this.computedMac) == 16*8
            && ba.equal(this.mac, this.computedMac);
    },

    toString: function(){
        return sprintf("ProcessDataResponse{statusCode=0x%4X, statusDetail=[%s], userObjectId: 0x%08X, function: [%s], " +
            "nonce: [%s], protectedData: [%s], plainData: [%s], mac: [%s], computedMac: [%s], macOK: %d",
            this.statusCode,
            this.statusDetail,
            this.userObjectID,
            this.function,
            sjcl.codec.hex.fromBits(this.nonce),
            sjcl.codec.hex.fromBits(this.protectedData),
            sjcl.codec.hex.fromBits(this.plainData),
            sjcl.codec.hex.fromBits(this.mac),
            sjcl.codec.hex.fromBits(this.computedMac),
            this.isMacOk()
        );
    }
});

/**
 * EB Import public key.
 */
eb.comm.pubKey = function(){};
eb.comm.pubKey.prototype = {
    id: undefined,
    type: undefined,
    certificate: undefined,
    key: undefined,

    toString: function(){
        return sprintf("pubKey{id=0x%x, type=[%s], certificate:[%s], key:[%s]",
            this.id,
            this.type,
            this.certificate ? sjcl.codec.hex.fromBits(this.certificate) : "null",
            this.key ? sjcl.codec.hex.fromBits(this.key) : "null"
        );
    }
};

/**
 * pubKey response.
 * @extends eb.comm.response
 */
eb.comm.pubKeyResponse = function(x){
    eb.misc.absorb(this, x);
};
eb.comm.pubKeyResponse.inheritsFrom(eb.comm.response, {
    /**
     * Plain data parsed from the response.
     * Nor MACed neither encrypted.
     * @output
     */
    keys: [],

    toString: function(){
        var stringKeys = [], index, len, c;
        for (index = 0, len =this.keys.length; index < len; ++index) {
            c = this.keys[index];
            if (c){
                stringKeys.push(c.toString());
            }
        }

        return sprintf("pubKeyResponse{statusCode=0x%4X, statusDetail=[%s], function: [%s], keys:[%s]",
            this.statusCode,
            this.statusDetail,
            this.function,
            stringKeys.join(", ")
        );
    }
});

/**
 * Raw EB Response parser.
 */
eb.comm.responseParser = function(){

};
eb.comm.responseParser.prototype = {
    /**
     * Parsed response
     * @output
     */
    response: null,

    /**
     * If set to true, response body parsing steps are logged to the console.
     * @input
     */
    debuggingLog: false,

    /**
     * Aux logging function
     * @input
     */
    logger: null,

    /**
     * User can define response parsing function here, called in the main parse body.
     * It is optional function callback, must return response.
     * @input
     */
    _responseParsingFunction: undefined,
    parsingFunction: function(x){
        this._responseParsingFunction = x;
        return this;
    },

    /**
     * Returns true if after parsing, code is OK.
     * @returns {boolean}
     */
    success: function(){
        return this.response.isCodeOk();
    },

    /**
     * Parses common JSON headers from the response, e.g., status, to the provided message.
     * @param resp
     * @param data
     * @returns {eb.comm.response}
     */
    parseCommonHeaders: function(resp, data){
        if (!data || !data.status || !data.function){
            throw new sjcl.exception.invalid("response data invalid");
        }

        // Build new response message.
        resp.statusCode = parseInt(data.status, 16);
        resp.statusDetail = data.statusdetail || "";
        resp.function = data.function;
        resp.result = data.result;
        return resp;
    },

    /**
     * Parse EB response
     *
     * @param data - json response
     * @returns request unwrapped response.
     */
    parse: function(data){
        var resp = this.response = new eb.comm.response();
        this.parseCommonHeaders(resp, data);

        // Build new response message.
        if (!this.success()){
            this._log("Error in processing, status: " + data.status + ", message: " + resp.statusDetail);
        }

        // If parsing function is already set, use it.
        if (this._responseParsingFunction){
            this.response = this._responseParsingFunction(data, resp, this);
            return this.response;
        }

        return resp;
    },

    _log:  function(x) {
        if (!this.debuggingLog){
            return;
        }

        if (console && console.log){
            console.log(x);
        }

        if (this.logger){
            this.logger(x);
        }
    }
};

/**
 * Parser parsing namely ProcessData response.
 * Data returned is encoded in the particular form, encrypted and MACed.
 * This response parser unwraps protected response.
 *
 * @param aesKey
 * @param macKey
 * @extends eb.comm.responseParser
 */
eb.comm.processDataResponseParser = function(aesKey, macKey){
    this.aesKey = aesKey || "";
    this.macKey = macKey || "";
};
eb.comm.processDataResponseParser.inheritsFrom(eb.comm.responseParser, {
    /**
     * Parsed user object ID, integer type.
     * @input
     */
    userObjectId : -1,

    /**
     * AES communication encryption key, hexcoded string.
     * @input
     */
    aesKey: "",

    /**
     * AES MAC communication key, hexcoded string.
     * @input
     */
    macKey: "",

    /**
     * Parse EB response
     *
     * @param data - json response
     * @returns request unwrapped response.
     */
    parse: function(data){
        var resp = this.response = new eb.comm.processDataResponse();
        this.parseCommonHeaders(resp, data);
        if (!this.success()){
            this._log("Error in processing, status: " + data.status + ", message: " + resp.statusDetail);
            return resp;
        }

        // Shortcuts.
        var h = sjcl.codec.hex;
        var ba = sjcl.bitArray;

        // Build new response message.
        var resultBuffer = resp.result;
        var baResult = h.toBits(resultBuffer.substring(0, resultBuffer.indexOf("_")));
        var plainLen = ba.extract(baResult, 0, 2*8);
        var plainBits = ba.bitSlice(baResult, 2*8, 2*8+plainLen*8);
        var protectedBits = ba.bitSlice(baResult, 2*8+plainLen*8);
        var protectedBitsBl = ba.bitLength(protectedBits);

        // Decrypt and verify
        var aesKeyBits = h.toBits(this.aesKey);
        var macKeyBits = h.toBits(this.macKey);
        var aes = new sjcl.cipher.aes(aesKeyBits);
        var aesMac = new sjcl.cipher.aes(macKeyBits);
        var hmac = new sjcl.misc.hmac_cbc(aesMac, 16, eb.padding.empty);

        // Verify MAC.
        var macTagOffset = protectedBitsBl - 16*8;
        var dataToMac = ba.bitSlice(protectedBits, 0, macTagOffset);
        if ((ba.bitLength(dataToMac) & 127) != 0){
            throw new sjcl.exception.corrupt("Padding size invalid");
        }

        resp.mac = ba.bitSlice(protectedBits, macTagOffset);
        if (ba.bitLength(resp.mac) != 16*8){
            throw new sjcl.exception.corrupt("MAC corrupted");
        }

        resp.computedMac = hmac.mac(dataToMac);
        if (!resp.mac || !ba.equal(resp.mac, resp.computedMac)){
            throw new sjcl.exception.corrupt("Padding is not valid"); //TODO: padding oracle?
        }

        // Decrypt.
        var dataToDecrypt = ba.bitSlice(protectedBits, 0, macTagOffset);
        if ((ba.bitLength(dataToDecrypt) & 127) != 0){
            throw new sjcl.exception.corrupt("Ciphertext block invalid");
        }

        // IV is null, nonce in the first block is kind of IV.
        var IV = h.toBits('00'.repeat(16));
        var decryptedData = sjcl.mode.cbc.decrypt(aes, dataToDecrypt, IV, [], false);
        this._log("decryptedData: " + h.fromBits(decryptedData) + ", len=" + ba.bitLength(decryptedData));

        // Check the flag.
        var responseFlag = ba.extract(decryptedData, 0, 8);
        if (responseFlag != 0xf1){
            throw new sjcl.exception.corrupt("Given data packet is not a response (flag mismatch)");
        }

        // Get user object.
        resp.userObjectID = ba.extract32(decryptedData, 8);

        // Get nonce, mangled.
        var returnedMangledNonce = ba.bitSlice(decryptedData, 5*8, 5*8+8*8);
        resp.nonce = eb.comm.demangleNonce(returnedMangledNonce);

        // Response = plainData + decryptedData.
        resp.protectedData = ba.bitSlice(decryptedData, 5*8+8*8);
        resp.plainData = plainBits;
        this._log("responseData: " + h.fromBits(resp.protectedData));

        return resp;
    }
});

/**
 * Simple connector to the EB interface.
 * Configurable for https/http GET/POST
 */
eb.comm.connector = function(){

};
eb.comm.connector.prototype = {
    objName: "connector",
    /**
     * Method to do REST request with. GET or POST are allowed.
     * @input
     */
    requestMethod: "POST",

    /**
     * Scheme used to contact remote API.
     * @input
     * @default https
     */
    requestScheme: "https",

    /**
     * Request timeout in milliseconds.
     * @input
     * @default 30000
     */
    requestTimeout: 30000,

    /**
     * Endpoint where EB API listens
     * @input
     */
    remoteEndpoint: "dragonfly.smarthsm.net",

    /**
     * Port of the remote endpoint
     * @input
     * @default 11180
     */
    remotePort: 11180,

    /**
     * Ajax call settings. User can modify default behavior by specifying settings here.
     * @input
     */
    ajaxSettings: {},

    /**
     * If set to true, request body building steps are logged.
     * @input
     */
    debuggingLog: false,

    /**
     * Aux logging function
     * @input
     */
    logger: null,

    /**
     * Request start time. Measure how long it took.
     * @output
     */
    requestTime: 0,

    /**
     * Raw request generated by the build call.
     * e.g., transmitted in the GET query method parameters / URL.
     */
    reqHeader: undefined,

    /**
     * Body part of the request.
     * e.g., transmitted in body of the HTTP message.
     */
    reqBody: undefined,

    /**
     * Response generated by response array.
     */
    response: undefined,

    /**
     * Response parser used to parse the response.
     * If not defined before calling doRequest method, default response parser is created.
     */
    responseParser: undefined,

    /**
     * Socket equivalent request, for debugging.
     * Generated when building the request.
     * @private
     */
    _socketRequest: "",

    _doneCallback: function(response, requestObj, jqXHR){},
    _failCallback: function(failType, jqXHR, textStatus, errorThrown, requestObj){},
    _alwaysCallback: function(requestObj){},

    done: function(x){
        this._doneCallback = x;
        return this;
    },

    fail: function(x){
        this._failCallback = x;
        return this;
    },

    always: function(x){
        this._alwaysCallback = x;
        return this;
    },

    /**
     * Returns if the EB returned with success.
     * Note: Data still may have invalid MAC.
     * @returns {*|boolean}
     */
    wasSuccessful: function(){
        return this.responseParser.success();
    },

    /**
     * Process configuration from the config object.
     * @param configObject java object with the configuration.
     */
    configure: function(configObject){
        if (!configObject){
            this._log("Invalid config object");
            return;
        }

        // Advanced connection settings.
        if ("remoteEndpoint" in configObject){
            this.remoteEndpoint = configObject.remoteEndpoint;
        }
        if ("remotePort" in configObject){
            this.remotePort = configObject.remotePort;
        }
        if ("requestMethod" in configObject){
            this.requestMethod = configObject.requestMethod;
        }
        if ("requestScheme" in configObject){
            this.requestScheme = configObject.requestScheme;
        }
        if ("requestTimeout" in configObject){
            this.requestTimeout = configObject.requestTimeout;
        }
        if ("debuggingLog" in configObject){
            this.debuggingLog = configObject.debuggingLog;
        }
        if ("logger" in configObject){
            this.logger = configObject.logger;
        }
        if ("responseParser" in configObject){
            this.responseParser = configObject.responseParser;
        }
        if ("reqHeader" in configObject){
            this.reqHeader = configObject.reqHeader;
        }
        if ("reqBody" in configObject){
            this.reqBody = configObject.reqBody;
        }
    },

    /**
     * Initializes state and builds request
     * @param requestHeader
     * @param requestBody
     */
    build: function(requestHeader, requestBody){
        if (requestHeader) {
            this.reqHeader = requestHeader;
        }

        if (requestBody) {
            this.reqBody = requestBody;
        }
    },

    /**
     * Builds EB request.
     *
     * @param requestHeader
     * @param requestBody
     * @returns request body string.
     */
    doRequest: function(requestHeader, requestBody){
        if (!this.reqBody){
            this.build(requestHeader, requestBody);
        }

        var url = this.getApiUrl();
        var apiData = this.getApiRequestData();
        var ajaxSettings = {
            url: url,
            type: this.requestMethod,
            dataType: 'json',
            timeout: this.requestTimeout,
            data: this.requestMethod == "POST" ? JSON.stringify(apiData) : null
        };

        // Extend ajax settings with user provided settings.
        $.extend(ajaxSettings, this.ajaxSettings || {});
        var ebc = this;

        // Do the remote call
        this._log("Sending remote request...");
        this.requestTime = new Date().getTime();
        $.ajax(ajaxSettings)
            .done(function (data, textStatus, jqXHR) {
                ebc._requestFinished();
                ebc._log("Response status: " + textStatus);
                ebc._log("Raw response: " + JSON.stringify(data));
                ebc.processAnswer(data, textStatus, jqXHR);

            }).fail(function (jqXHR, textStatus, errorThrown) {
            ebc._requestFinished();
            ebc._log("Error: " + sprintf("Error: status=[%d], responseText: [%s], error: [%s], status: [%s] misc: %s",
                    jqXHR.status, jqXHR.responseText, errorThrown, textStatus, JSON.stringify(jqXHR)));

            ebc.processFail(jqXHR, textStatus, errorThrown);
            if (ebc._failCallback) {
                ebc._failCallback(0x1, jqXHR, textStatus, errorThrown, ebc);
            }

        }).always(function (data, textStatus, jqXHR) {
            ebc.processAlways(data, textStatus, jqXHR);
            if (ebc._alwaysCallback) {
                ebc._alwaysCallback(ebc);
            }
        });
    },

    /**
     * Request finished, measure time.
     * @private
     */
    _requestFinished: function(){
        this.requestTime = (new Date().getTime() - this.requestTime);
        this._log("Request finished in " + this.requestTime + " ms");
    },

    /**
     * Processing response from the server.
     *
     * @param data
     * @param textStatus
     * @param jqXHR
     */
    processAnswer: function(data, textStatus, jqXHR){
        try {
            var h = sjcl.codec.hex;

            // Build a new EB request.
            var responseParser = this.getResponseParser();
            this.response = responseParser.parse(data);

            if (responseParser.success()) {
                this._log("Processing complete, response: " + this.response.toString());
                if (this._doneCallback){
                    this._doneCallback(this.response, this, jqXHR)
                }

            } else {
                this._log("Failure, status: " + this.response.toString());
                if (this._failCallback){
                    this._failCallback(0x2, jqXHR, textStatus, this.response, this);
                }
            }

        } catch(e){
            this._log("Exception when processing the response: " + e);
            if (this._failCallback){
                this._failCallback(0x3, jqXHR, textStatus, e, this);
            }

            throw e;
        }
    },

    /**
     * To be overriden.
     * @param jqXHR
     * @param textStatus
     * @param errorThrown
     */
    processFail: function(jqXHR, textStatus, errorThrown){

    },

    /**
     * To be overriden.
     * @param data
     * @param textStatus
     * @param jqXHR
     */
    processAlways: function(data, textStatus, jqXHR){

    },

    /**
     * Returns remote API URL to query with Ajax.
     * According to current request settings.
     * Note: Request has to be built when calling this function.
     *
     * @returns {*}
     */
    getApiUrl: function(){
        return sprintf("%s://%s:%d/",
            this.requestScheme,
            this.remoteEndpoint,
            this.remotePort);
    },

    /**
     * Returns Ajax request data.
     * According to current request settings.
     * Note: Request has to be built when calling this function.
     *
     * @returns {*}
     */
    getApiRequestData: function(){
        return this.reqBody;
    },

    /**
     * Returns response parser when is needed. May lazily initialize parser.
     * Override point.
     *
     * @returns {*}
     */
    getResponseParser: function(){
        this.responseParser = new eb.comm.responseParser();
        this.responseParser.debuggingLog = true;
        this.responseParser.logger = this.logger;
        return this.responseParser;
    },

    /**
     * Returns raw EB request for raw socket transport method.
     * For debugging & verification.
     *
     * @returns {string}
     */
    getSocketRequest: function(){
        this._socketRequest = {};
        $.extend(this._socketRequest, this.reqHeader || {});
        $.extend(this._socketRequest, this.reqBody || {});
        return this._socketRequest;
    },

    /**
     * Logger wrapper. Allowing to log messages both to console and provided logger.
     * @param x message to log.
     * @private
     */
    _log:  function(x) {
        if (!this.debuggingLog){
            return;
        }

        if (console && console.log){
            console.log(x);
        }

        if (this.logger){
            this.logger(x);
        }
    }
};

/**
 * API request using the connector.
 * Standard request with
 *   - API version,
 *   - API Key,
 *   - API lower 4 bytes identifier (e.g., user object id),
 *   - call function,
 *   - nonce
 *
 * @param apiKey
 * @param apiKeyLow4Bytes
 */
eb.comm.apiRequest = function(apiKey, apiKeyLow4Bytes){
    this.apiKey = apiKey;
    this.apiKeyLow4Bytes = apiKeyLow4Bytes;
};
eb.comm.apiRequest.inheritsFrom(eb.comm.connector, {
    objName: "apiRequest",

    /**
     * Function to call
     * @input
     * @default ProcessData
     */
    callFunction: "ProcessData",

    /**
     * User API key
     * @input
     */
    apiKey: undefined,

    /**
     * Lower 4 API bytes to use for api token.
     * For process data this may be UseObjectId.
     * @input
     */
    apiKeyLow4Bytes: undefined,

    /**
     * Version of EB API.
     * @input
     * @default 1.0
     */
    apiVersion: "1.0",

    /**
     * Nonce generated for the request.
     * @input
     * @output
     */
    nonce: undefined,

    /**
     * Composite API key for the request.
     * Generated before request is sent.
     * @private
     */
    _apiKeyReq: "",

    /**
     * Builds API key token.
     * Consists of apiKey and low4B identifier.
     * Can be specified by parameters or currently set values are set.
     * Result is returned and set to the property.
     *
     * @param apiKey
     * @param apiLow4b
     */
    buildApiBlock: function(apiKey, apiLow4b){
        apiKey = apiKey || this.apiKey;
        apiLow4b = apiLow4b || this.apiKeyLow4Bytes;
        this._apiKeyReq = sprintf("%s%010x", apiKey, apiLow4b);
        return this._apiKeyReq;
    },

    /**
     * Builds standard request header from existing fields.
     */
    buildReqHeader: function() {
        this.reqHeader = {
            objectid:this._apiKeyReq,
            function:this.callFunction,
            nonce:this.getNonce(),
            version:this.apiVersion
        };
        return this.reqHeader;
    },

    /**
     * Returns currently set nonce.
     * Generates a new one if is undefined.
     * @returns {*}
     */
    getNonce: function(){
        if (!this.nonce){
            return this.genNonce();
        }

        return this.nonce;
    },

    /**
     * Generates new nonce, sets it as a current nonce for the request.
     * @returns {string|*|string}
     */
    genNonce: function(){
        this.nonce = eb.misc.genHexNonce(16);
        return this.nonce;
    },

    /**
     * Process configuration from the config object.
     * @param configObject java object with the configuration.
     */
    configure: function(configObject){
        if (!configObject){
            this._log("Invalid config object");
            return;
        }

        // Configure with parent.
        eb.comm.apiRequest.superclass.configure.call(this, configObject);

        // Configure this.
        if ("callFunction" in configObject){
            this.callFunction = configObject.callFunction;
        }
        if ("apiKey" in configObject){
            this.apiKey = configObject.apiKey;
        }
        if ("apiKeyLow4Bytes" in configObject){
            this.apiKeyLow4Bytes = configObject.apiKeyLow4Bytes;
        }
        if ("nonce" in configObject){
            this.nonce = configObject.nonce;
        }
    },

    /**
     * Returns remote API URL to query with Ajax.
     * According to current request settings.
     * Note: Request has to be built when calling this function.
     *
     * @returns {*}
     */
    getApiUrl: function(){
        if (this.requestMethod == "POST" || (this.requestMethod == "GET" && !this.reqBody)){
            return sprintf("%s://%s:%d/%s/%s/%s/%s",
                this.requestScheme,
                this.remoteEndpoint,
                this.remotePort,
                this.apiVersion,
                this._apiKeyReq,
                this.callFunction,
                this.getNonce());

        } else if (this.requestMethod == "GET"){
            return sprintf("%s://%s:%d/%s/%s/%s/%s/%s",
                this.requestScheme,
                this.remoteEndpoint,
                this.remotePort,
                this.apiVersion,
                this._apiKeyReq,
                this.callFunction,
                this.getNonce(),
                JSON.stringify(this.reqBody));

        } else {
            throw new eb.exception.invalid("Invalid configuration, unknown method: " + this.requestMethod);
        }
    },

    /**
     * Returns Ajax request data.
     * According to current request settings.
     * Note: Request has to be built when calling this function.
     *
     * @returns {*}
     */
    getApiRequestData: function(){
        if (this.requestMethod == "POST") {
            return this.reqBody;
        } else {
            return {};
        }
    },

    /**
     * Initializes state and builds request
     * @param requestHeader
     * @param requestBody
     */
    build: function(requestHeader, requestBody){
        if (requestHeader.apiKey && requestHeader.apiKeyLow4Bytes){
            this.buildApiBlock(requestHeader.apiKey, requestHeader.apiKeyLow4Bytes);
        } else {
            this.buildApiBlock();
        }

        if (requestBody){
            this.reqBody = requestBody;
        }

        if (requestHeader){
            this.reqHeader = requestHeader;
        }

        this.buildReqHeader();
    },
});

/**
 * Process data request to the EB.
 * @param apiKey
 * @param aesKey
 * @param macKey
 * @param userObjectId
 */
eb.comm.processData = function(apiKey, aesKey, macKey, userObjectId){
    this.apiKey = apiKey || "";
    this.aesKey = aesKey || "";
    this.macKey = macKey || "";
    this.userObjectId = userObjectId || -1;
    this.callFunction = "ProcessData";
};
eb.comm.processData.inheritsFrom(eb.comm.apiRequest, {
    /**
     * User object ID to perform operation with, integer type.
     * @input
     */
    userObjectId : -1,

    /**
     * AES communication encryption key, hexcoded string.
     * @input
     */
    aesKey: "",

    /**
     * AES MAC communication key, hexcoded string.
     * @input
     */
    macKey: "",

    /**
     * Type of the data request.
     * PLAINAES for AES keys, RSA2048 for RSA-2048 keys.
     *
     * @input
     * @default PLAINAES
     */
    callRequestType: "PLAINAES",

    /**
     * Request builder used to build the request.
     * @output
     */
    processDataRequestBodyBuilder: null,

    /**
     * Request block generated by request builder.
     * @private
     */
    _requestBlock: "",

    /**
     * Process configuration from the config object.
     * @param configObject java object with the configuration.
     */
    configure: function(configObject){
        if (!configObject){
            this._log("Invalid config object");
            return;
        }

        var toConfig = configObject;
        if ("userObjectId" in configObject){
            toConfig = $.extend(toConfig, {apiKeyLow4Bytes : configObject.userObjectId});
        }

        // Configure with parent.
        eb.comm.processData.superclass.configure.call(this, toConfig);

        // Configure this.
        if ("aesKey" in configObject){
            this.aesKey = configObject.aesKey;
        }
        if ("macKey" in configObject){
            this.macKey = configObject.macKey;
        }
        if ("userObjectId" in configObject){
            this.userObjectId = configObject.userObjectId;
            this.apiKeyLow4Bytes = configObject.userObjectId;
        }
        if ("callRequestType" in configObject){
            this.callRequestType = configObject.callRequestType;
        }
    },

    /**
     * Initializes state and builds request
     * @param plainData
     * @param requestData
     */
    build: function(plainData, requestData){
        this._log("Building request body");

        // Request header data.
        this.buildApiBlock(this.apiKey, this.userObjectId);
        this.buildReqHeader();

        // Build a new EB request.
        this.processDataRequestBodyBuilder = new eb.comm.processDataRequestBodyBuilder();
        this.processDataRequestBodyBuilder.aesKey = this.aesKey;
        this.processDataRequestBodyBuilder.macKey = this.macKey;
        this.processDataRequestBodyBuilder.userObjectId = this.userObjectId;
        this.processDataRequestBodyBuilder.reqType = this.callRequestType;
        this.processDataRequestBodyBuilder.debuggingLog = this.debuggingLog;
        this.processDataRequestBodyBuilder.logger = this.logger;
        this.processDataRequestBodyBuilder.nonce = this.getNonce();

        this._requestBlock = this.processDataRequestBodyBuilder.build(plainData, requestData);
        this.reqBody = {data : this._requestBlock};

        var nonce = this.getNonce();
        var url = this.getApiUrl();
        var apiData = this.getApiRequestData();

        this._log("Nonce: " + nonce);
        this._log("URL: " + url + ", method: " + this.requestMethod);
        this._log("UserData: " + JSON.stringify(apiData));
        this._log("SocketReq: " + JSON.stringify(this.getSocketRequest()));
    },

    /**
     * Builds EB request.
     *
     * @param requestHeader
     * @param requestBody
     * @returns request body string.
     */
    doRequest: function(requestHeader, requestBody){
        if (!this.reqBody){
            this.build(requestHeader, requestBody);
        }

        eb.comm.processData.superclass.doRequest.call(this);
    },

    /**
     * Returns remote API URL to query with Ajax.
     * According to current request settings.
     * Note: Request has to be built when calling this function.
     *
     * @returns {*}
     */
    getApiUrl: function(){
        if (this.requestMethod == "POST"){
            return sprintf("%s://%s:%d/%s/%s/%s/%s",
                this.requestScheme,
                this.remoteEndpoint,
                this.remotePort,
                this.apiVersion,
                this._apiKeyReq,
                this.callFunction,
                this.getNonce());

        } else if (this.requestMethod == "GET"){
            return sprintf("%s://%s:%d/%s/%s/%s/%s/%s",
                this.requestScheme,
                this.remoteEndpoint,
                this.remotePort,
                this.apiVersion,
                this._apiKeyReq,
                this.callFunction,
                this.getNonce(),
                this.reqBody.data);

        } else {
            throw new eb.exception.invalid("Invalid configuration, unknown method: " + this.requestMethod);
        }
    },

    /**
     * Returns Ajax request data.
     * According to current request settings.
     * Note: Request has to be built when calling this function.
     *
     * @returns {*}
     */
    getApiRequestData: function(){
        if (this.requestMethod == "POST") {
            return this.reqBody;
        } else {
            return {};
        }
    },

    /**
     * Returns response parser when is needed. May lazily initialize parser.
     * Override point.
     *
     * @returns {*}
     */
    getResponseParser: function(){
        this.responseParser = new eb.comm.processDataResponseParser();
        this.responseParser.debuggingLog = true;
        this.responseParser.logger = this.logger;
        this.responseParser.aesKey = this.aesKey;
        this.responseParser.macKey = this.macKey;
        return this.responseParser;
    }
});

/**
 * Request obtaining import public keys.
 */
eb.comm.getPubKey = function(){
    this.callFunction = "GetImportPublicKey";
};
eb.comm.getPubKey.inheritsFrom(eb.comm.apiRequest, {
    objName: "getPubKey",

    /**
     * Initializes state and builds request
     */
    build: function(){
        this._log("Building request body");

        // Request header data.
        this.buildApiBlock(this.apiKey, this.userObjectId);
        this.buildReqHeader();
        this.reqBody = {};

        var nonce = this.getNonce();
        var url = this.getApiUrl();
        this._log("Nonce generated: " + nonce);
        this._log("URL: " + url + ", method: " + this.requestMethod);
        this._log("SocketReq: " + JSON.stringify(this.getSocketRequest()));
    },

    /**
     * Returns response parser when is needed. May lazily initialize parser.
     * Override point.
     *
     * @returns {*}
     */
    getResponseParser: function(){
        // Generic parser with given parsing function.
        var pubKeyParser = new eb.comm.responseParser();
        pubKeyParser.parsingFunction(function(data, resp, parser){
            var response = new eb.comm.pubKeyResponse(resp);

            /**
             * Response:
             * {"function":"GetImportPublicKey","result":[
             * {"certificate":null,"id":263,"type":"rsa","key":"81 00 03 01 00 01 82 01 00 e1 e0 6b 76 f9 7b cd 82 7c 98 cc 3b 41 a8 50 40 cc dc 61 cf 72 58 14 fd b9 e9 5f 53 06 29 12 e9 39 b1 3c f1 ce 27 d0 7b 44 78 57 7a 20 9c ff db de a2 90 29 19 c0 87 08 8f 85 d5 ed 1d 0b 0c dc ef d8 23 b6 49 71 4f 69 95 31 d9 b8 10 08 af 63 5e a9 79 67 82 fe 3c 40 3c 0e 5d e2 15 58 78 06 f3 0e 16 09 4d a0 16 05 89 e9 80 1c ba f4 0e 63 fd 2d 72 cb 85 cb 7f c1 9a 37 7b 0f a9 2e 7d 90 8e 6a 69 aa bc 4c 5b a2 2d 32 e5 58 7e 0e d8 12 b4 c1 62 66 84 98 fd e5 54 08 93 c1 c0 88 41 51 60 93 93 d8 cc cd ee 3e eb 88 ae 91 24 32 16 b2 26 92 73 f9 a5 23 b9 5c cf e5 b1 f9 e5 4f d2 4f 73 77 a2 ab d7 c6 43 9e c4 60 97 c4 70 1e 58 c2 49 33 02 2d 43 8b 77 67 3c 30 0e a6 81 e4 73 d2 46 18 f9 79 40 3d a6 79 dd 5c 3c e0 b7 4c 16 a9 5c 96 47 40 7c 2c dc 11 3b 92 75 44 ec d8 c6 95 "},
             * {"certificate":null,"id":264,"type":"rsa","key":"81 00 03 01 00 01 82 01 00 e1 e0 6b 76 f9 7b cd 82 7c 98 cc 3b 41 a8 50 40 cc dc 61 cf 72 58 14 fd b9 e9 5f 53 06 29 12 e9 39 b1 3c f1 ce 27 d0 7b 44 78 57 7a 20 9c ff db de a2 90 29 19 c0 87 08 8f 85 d5 ed 1d 0b 0c dc ef d8 23 b6 49 71 4f 69 95 31 d9 b8 10 08 af 63 5e a9 79 67 82 fe 3c 40 3c 0e 5d e2 15 58 78 06 f3 0e 16 09 4d a0 16 05 89 e9 80 1c ba f4 0e 63 fd 2d 72 cb 85 cb 7f c1 9a 37 7b 0f a9 2e 7d 90 8e 6a 69 aa bc 4c 5b a2 2d 32 e5 58 7e 0e d8 12 b4 c1 62 66 84 98 fd e5 54 08 93 c1 c0 88 41 51 60 93 93 d8 cc cd ee 3e eb 88 ae 91 24 32 16 b2 26 92 73 f9 a5 23 b9 5c cf e5 b1 f9 e5 4f d2 4f 73 77 a2 ab d7 c6 43 9e c4 60 97 c4 70 1e 58 c2 49 33 02 2d 43 8b 77 67 3c 30 0e a6 81 e4 73 d2 46 18 f9 79 40 3d a6 79 dd 5c 3c e0 b7 4c 16 a9 5c 96 47 40 7c 2c dc 11 3b 92 75 44 ec d8 c6 95 "}]
             * ,"status":"9000","statusdetail":"(OK)SW_STAT_OK","version":"1.0"}
             */
            if (!data.result || !data.result.length) {
                parser._log("Result is not an array");
                return;
            }

            response.keys = [];
            var index, len, cur, cKey, ok;
            for (index = 0, len = data.result.length; index < len; ++index) {
                cur = data.result[index];
                cKey = new eb.comm.pubKey();
                if (!("id" in cur && "key" in cur)){
                    continue;
                }

                cKey.id = cur.id;
                cKey.type = cur.type;
                if ("certificate" in cur && cur.certificate){
                    var noSpaceCrt = cur.certificate.replace(/\s+/g,'');
                    cKey.certificate = sjcl.codec.hex.toBits(noSpaceCrt);
                }

                if ("key" in cur && cur.key){
                    var noSpaceKey = cur.key.replace(/\s+/g,'');
                    cKey.key = sjcl.codec.hex.toBits(noSpaceKey);
                }

                response.keys.push(cKey);
            }
            return response;
        });

        this.responseParser = pubKeyParser;
        return this.responseParser;
    }
});

