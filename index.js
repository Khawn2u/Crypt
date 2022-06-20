var Crypt = function() {
	var self = this;
	this.mod = function(a,m) {
		var result = a%m;
		if (result < 0) {
			return result+m;
		} else {
			return result;
		}
	}
	this.modInverse = function(a,mod) {
		a = self.mod(a,mod);
		var b = mod;
		var x = 0n;
		var y = 1n;
		var u = 1n;
		var v = 0n;
		while (a != 0) {
			var q = b/a;
			var r = b%a;
			var m = x-(u*q);
			var n = y-(v*q);
			b = a;
			a = r;
			x = u;
			y = v;
			u = m;
			v = n;
		}
		return self.mod(x,mod);
	}
	this.gcd = function(a,b) {
		if (b == 0) {
			return a;
		} else {
			return self.gcd(b, a%b);
		}
	}
	this.modPow = function(a,n,m) {
		if (n < 1) {
			return 0n;
		}
		var result = a;
		n = n.toString(2);
		for (var i=1; i<n.length; i++) {
			result = (result*result)%m;
			if (n[i] == '1') {
				result = (result*a)%m;
			}
		}
		return result;
	}
	this.modOrder = function(b,p) {
		if (self.gcd(b,p) != 1) {
			return -1n;
		}
		var k = 3n;
		var val = (((b*b)%p)*b)%p;
		while (true) {
			val = (val*b)%p;
			if (val == 1n) {
				return k;
			}
			if (val == 0n) {
				return -1n;
			}
			k++;
		}
	}
	this.modSqrt = function(n,p) {
		if (self.gcd(n,p) != 1 || self.modPow(n,(p-1n)/2n,p) == (p-1n)) {
			console.log("-1");
			return -1n;
		}
		var s = p-1n;
		var e = 0n;
		while (s%2n == 0n) {
			s >>= 1n;
			e++;
		}
		var expon = (p-1n)/2n;
		var pminusone = p-1n;
		var q=2n;
		for (; true; q++) {
			if (self.modPow(q,expon,p) == pminusone) {
				break;
			}
		}
		var x = self.modPow(n,(s+1n)/2n,p);
		var b = self.modPow(n,s,p);
		var g = self.modPow(q,s,p);
		var r = e;
		while (true) {
			var m;
			for (m=0n; m<r; m++) {
				var ordr = self.modOrder(b,p);
				if (ordr == -1n) {
					return -1n;
				}
				if (ordr == (2n**m)) {
					break;
				}
			}
			if (m <= 1n) {
				return x;
			}
			x = (x*self.modPow(g,2n**((r-m)-1n),p))%p;
			g = self.modPow(g,2n**(r-m),p);
			b = (b*g)%p;
			if (b == 1n) {
				return x;
			}
			r = m;
		}
	}
	this.randomBytes = function(len) {
		return new Uint8Array(len).map(function(){return Math.floor(Math.random()*256)})
	}
	this.bufferToBigInt = function(buff) {
		var result = 0n;
		for (var i=0; i<buff.length; i++) {
			result *= 256n;
			result += BigInt(buff[i]);
		}
		return result;
	}
	this.ECurve = function(a,b,m) {
		this.a = a;
		this.b = b;
		this.m = m;
		this.add = function(a,b) {
			if ((a[0] == b[0]) && (a[1] == b[1])) {
				return this.double(a);
			}
			if ((a[0] == 0) && (a[1] == 0)) {
				return b;
			}
			if ((b[0] == 0) && (b[1] == 0)) {
				return a;
			}
			var l = (b[1]-a[1])*self.modInverse(b[0]-a[0],this.m);
			var x = (l*l)-(a[0]+b[0]);
			var y = (l*(a[0]-x))-a[1];
			return [self.mod(x,this.m),self.mod(y,this.m)];
		}
		this.double = function(p) {
			if ((p[0] == 0) && (p[1] == 0)) {
				return [0n,0n];
			}
			var l = ((3n*p[0]*p[0])+this.a)*self.modInverse(p[1]+p[1],this.m);
			var x = (l*l)-(2n*p[0]);
			var y = (l*(p[0]-x))-p[1];
			return [self.mod(x,this.m),self.mod(y,this.m)];
		}
		this.multiply = function(p,n) {
			if (n < 1n) {
				return [0n,0n];
			}
			var m = -1n;
			var q = n;
			while (q) {
				m++;
				q >>= 1n;
			}
			var result = p;
			while (m > 0n) {
				m--;
				result = this.double(result);
				if ((n>>m)&1n) {
					result = this.add(result,p);
				}
			}
			return result;
		}
		this.isOnCurve = function(p) {
			return (p[1]*p[1])%this.m == ((p[0]*p[0]*p[0])+(this.a*p[0])+this.b)%this.m;
		}
	}
	this.PublicCurve = function(curve,genoratorPoint,order) {
		this.curve = curve;
		this.g = genoratorPoint;
		this.n = order;
		this.Hash = null;
		this.setSignHashFunction = function(hashFunct) {
			this.Hash = hashFunct;
		}
		this.getPublicKey = function(sk) {
			return this.curve.multiply(this.g,sk);
		}
		this.toAdress = function(pk) {
			var ad = pk[0];
			if (this.adressToPublicKey(ad)[1] != pk[1]) {
				ad += this.curve.m;
			}
			return "0x"+ad.toString(16);
		}
		this.adressToPublicKey = function(x) {
			x = BigInt(x);
			var isnegitive = x >= this.curve.m;
			x = x%this.curve.m;
			var y = self.modSqrt(self.mod((x*x*x)+(this.curve.a*x)+this.curve.b,this.curve.m),this.curve.m);
			if (y < 0n) {
				return [0n,0n];
			}
			if (isnegitive) {
				return [x,this.curve.m-y];
			} else {
				return [x,y];
			}
		}
		this.sign = function(message,sk) {
			if (!this.Hash) {
				throw new Error("No Hash set for this PublicCurve, try running PublicCurve.setSignHashFunction(HashFunction) to fix this. HashFunction can be any function but if your lazy just use Crypt.Keccak256 or Crypt.Keccak384");
			}
			var msg = self.bufferToBigInt(this.Hash(message));
			var k = (self.bufferToBigInt(self.randomBytes(this.OrderBytes))%(this.n-1n))+1n;
			var kG = this.curve.multiply(this.g,k);
			var r = kG[0]%this.n;
			if (r == 0n) {
				return this.sign(message,sk);
			}
			var kinv = self.modInverse(k,this.n);
			var s = self.mod(kinv*(msg+(r*sk)),this.n);
			if (s == 0n) {
				return this.sign(message,sk);
			}
			var signiture = ((s*this.n)+r);
			var pk = this.getPublicKey(sk);
			if (this.adressToPublicKey(pk[0])[1] != pk[1]) {
				signiture += this.n*this.n;
			}
			return {
				Message:message,
				Signiture:"0x"+signiture.toString(16)
			};
		}
		this.recoverPublicKey = function(signiture) {
			var msg = self.bufferToBigInt(this.Hash(signiture.Message));
			var sign = BigInt(signiture.Signiture);
			var isnegitive = (sign >= this.n*this.n);
			var r = sign%this.n;
			var s = (sign/this.n)%this.n;
			var R = [r,self.modSqrt(self.mod((r*r*r)+(this.curve.a*r)+this.curve.b,this.curve.m),this.curve.m)];
			if (isnegitive) {
				R[1] = this.curve.m-R[1];
			}
			var z = msg%this.n;
			var rinv = self.modInverse(r,this.n);
			var sR = this.curve.multiply(R,s);
			var zG = this.curve.multiply(this.g,z);
			if (!isnegitive) {
				zG[1] = this.curve.m-zG[1];
			}
			var pk = this.curve.multiply(this.curve.add(sR,zG),rinv);
			if (isnegitive) {
				pk[1] = this.curve.m-pk[1];
			}
			return pk;
		}
		this.verify = function(signiture,pk) {
			var msg = self.bufferToBigInt(this.Hash(signiture.Message));
			var sign = BigInt(signiture.Signiture);
			var r = sign%this.n;
			var s = (sign/this.n)%this.n;
			var w = self.modInverse(s,this.n);
			var u1 = self.mod(msg*w,this.n);
			var u2 = self.mod(r*w,this.n);
			var p0 = this.curve.multiply(this.g,u1);
			var p1 = this.curve.multiply(pk,u2);
			var X = this.curve.add(p0,p1);
			var v = X[0]%this.n;
			return v == r && v != 0n;
		}
	}
	this.SignedMessageToBuffer = function(signiture) {
		var msg = signiture.Message;
		if (msg.constructor === String) {
			if (typeof window === 'undefined') {
				msg = Buffer.from(msg,'utf-8');
			} else {
				msg = (new TextEncoder()).encode(msg);
			}
		}
		var BufferA = self.bigIntToBuffer(BigInt(signiture.Signiture));
		var result = new Uint8Array(msg.length+BufferA.length+1);
		result[0] = BufferA.length;
		result.set(BufferA,1);
		result.set(msg,BufferA.length+1);
		return result;
	}
	this.BufferToSignedMessage = function(buffer) {
		var len = buffer[0]+1;
		var msg = buffer.subarray(len);
		var sign = buffer.subarray(1,len);
		return {
			Message:msg,
			Signiture:"0x"+self.bufferToBigInt(sign).toString(16)
		};
	}
	this.toHex = function(arr) {
		var result = "";
		for (var i=0; i<arr.length; i++) {
			result += ("0"+arr[i].toString(16)).slice(-2);
		}
		return result;
	}
	this.bigIntToBuffer = function(BI) {
		var result = [];
		while (BI > 0) {
			result.unshift(Number(BI%256n));
			BI >>= 8n;
		}
		return new Uint8Array(result);
	}
	this.Hash = {
		SHIFT:[0, 8, 16, 24],
		RC:[1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648, 2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648],
		f:function (s) {
				var h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9,
				b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17,
				b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33,
				b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;
				for (n = 0; n < 48; n += 2) {
					c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40]; c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41]; c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42]; c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43]; c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44]; c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45]; c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46]; c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47]; c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48]; c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49]; h = c8 ^ ((c2 << 1) | (c3 >>> 31)); l = c9 ^ ((c3 << 1) | (c2 >>> 31)); s[0] ^= h; s[1] ^= l; s[10] ^= h; s[11] ^= l; s[20] ^= h; s[21] ^= l; s[30] ^= h; s[31] ^= l; s[40] ^= h; s[41] ^= l; h = c0 ^ ((c4 << 1) | (c5 >>> 31)); l = c1 ^ ((c5 << 1) | (c4 >>> 31)); s[2] ^= h; s[3] ^= l; s[12] ^= h; s[13] ^= l; s[22] ^= h; s[23] ^= l; s[32] ^= h; s[33] ^= l; s[42] ^= h; s[43] ^= l; h = c2 ^ ((c6 << 1) | (c7 >>> 31)); l = c3 ^ ((c7 << 1) | (c6 >>> 31)); s[4] ^= h; s[5] ^= l; s[14] ^= h; s[15] ^= l; s[24] ^= h; s[25] ^= l; s[34] ^= h; s[35] ^= l; s[44] ^= h; s[45] ^= l; h = c4 ^ ((c8 << 1) | (c9 >>> 31)); l = c5 ^ ((c9 << 1) | (c8 >>> 31)); s[6] ^= h; s[7] ^= l; s[16] ^= h; s[17] ^= l; s[26] ^= h; s[27] ^= l; s[36] ^= h; s[37] ^= l; s[46] ^= h; s[47] ^= l; h = c6 ^ ((c0 << 1) | (c1 >>> 31)); l = c7 ^ ((c1 << 1) | (c0 >>> 31)); s[8] ^= h; s[9] ^= l; s[18] ^= h; s[19] ^= l; s[28] ^= h; s[29] ^= l; s[38] ^= h; s[39] ^= l; s[48] ^= h; s[49] ^= l; b0 = s[0]; b1 = s[1]; b32 = (s[11] << 4) | (s[10] >>> 28); b33 = (s[10] << 4) | (s[11] >>> 28); b14 = (s[20] << 3) | (s[21] >>> 29); b15 = (s[21] << 3) | (s[20] >>> 29); b46 = (s[31] << 9) | (s[30] >>> 23); b47 = (s[30] << 9) | (s[31] >>> 23); b28 = (s[40] << 18) | (s[41] >>> 14); b29 = (s[41] << 18) | (s[40] >>> 14); b20 = (s[2] << 1) | (s[3] >>> 31); b21 = (s[3] << 1) | (s[2] >>> 31); b2 = (s[13] << 12) | (s[12] >>> 20); b3 = (s[12] << 12) | (s[13] >>> 20); b34 = (s[22] << 10) | (s[23] >>> 22); b35 = (s[23] << 10) | (s[22] >>> 22); b16 = (s[33] << 13) | (s[32] >>> 19); b17 = (s[32] << 13) | (s[33] >>> 19); b48 = (s[42] << 2) | (s[43] >>> 30); b49 = (s[43] << 2) | (s[42] >>> 30); b40 = (s[5] << 30) | (s[4] >>> 2); b41 = (s[4] << 30) | (s[5] >>> 2); b22 = (s[14] << 6) | (s[15] >>> 26); b23 = (s[15] << 6) | (s[14] >>> 26); b4 = (s[25] << 11) | (s[24] >>> 21); b5 = (s[24] << 11) | (s[25] >>> 21); b36 = (s[34] << 15) | (s[35] >>> 17); b37 = (s[35] << 15) | (s[34] >>> 17); b18 = (s[45] << 29) | (s[44] >>> 3); b19 = (s[44] << 29) | (s[45] >>> 3); b10 = (s[6] << 28) | (s[7] >>> 4); b11 = (s[7] << 28) | (s[6] >>> 4); b42 = (s[17] << 23) | (s[16] >>> 9); b43 = (s[16] << 23) | (s[17] >>> 9); b24 = (s[26] << 25) | (s[27] >>> 7); b25 = (s[27] << 25) | (s[26] >>> 7); b6 = (s[36] << 21) | (s[37] >>> 11); b7 = (s[37] << 21) | (s[36] >>> 11); b38 = (s[47] << 24) | (s[46] >>> 8); b39 = (s[46] << 24) | (s[47] >>> 8); b30 = (s[8] << 27) | (s[9] >>> 5); b31 = (s[9] << 27) | (s[8] >>> 5); b12 = (s[18] << 20) | (s[19] >>> 12); b13 = (s[19] << 20) | (s[18] >>> 12); b44 = (s[29] << 7) | (s[28] >>> 25); b45 = (s[28] << 7) | (s[29] >>> 25); b26 = (s[38] << 8) | (s[39] >>> 24); b27 = (s[39] << 8) | (s[38] >>> 24); b8 = (s[48] << 14) | (s[49] >>> 18); b9 = (s[49] << 14) | (s[48] >>> 18); s[0] = b0 ^ (~b2 & b4); s[1] = b1 ^ (~b3 & b5); s[10] = b10 ^ (~b12 & b14); s[11] = b11 ^ (~b13 & b15); s[20] = b20 ^ (~b22 & b24); s[21] = b21 ^ (~b23 & b25); s[30] = b30 ^ (~b32 & b34); s[31] = b31 ^ (~b33 & b35); s[40] = b40 ^ (~b42 & b44); s[41] = b41 ^ (~b43 & b45); s[2] = b2 ^ (~b4 & b6); s[3] = b3 ^ (~b5 & b7); s[12] = b12 ^ (~b14 & b16); s[13] = b13 ^ (~b15 & b17); s[22] = b22 ^ (~b24 & b26); s[23] = b23 ^ (~b25 & b27); s[32] = b32 ^ (~b34 & b36); s[33] = b33 ^ (~b35 & b37); s[42] = b42 ^ (~b44 & b46); s[43] = b43 ^ (~b45 & b47); s[4] = b4 ^ (~b6 & b8); s[5] = b5 ^ (~b7 & b9); s[14] = b14 ^ (~b16 & b18); s[15] = b15 ^ (~b17 & b19); s[24] = b24 ^ (~b26 & b28); s[25] = b25 ^ (~b27 & b29); s[34] = b34 ^ (~b36 & b38); s[35] = b35 ^ (~b37 & b39); s[44] = b44 ^ (~b46 & b48); s[45] = b45 ^ (~b47 & b49); s[6] = b6 ^ (~b8 & b0); s[7] = b7 ^ (~b9 & b1); s[16] = b16 ^ (~b18 & b10); s[17] = b17 ^ (~b19 & b11); s[26] = b26 ^ (~b28 & b20); s[27] = b27 ^ (~b29 & b21); s[36] = b36 ^ (~b38 & b30); s[37] = b37 ^ (~b39 & b31); s[46] = b46 ^ (~b48 & b40); s[47] = b47 ^ (~b49 & b41); s[8] = b8 ^ (~b0 & b2); s[9] = b9 ^ (~b1 & b3); s[18] = b18 ^ (~b10 & b12); s[19] = b19 ^ (~b11 & b13); s[28] = b28 ^ (~b20 & b22); s[29] = b29 ^ (~b21 & b23); s[38] = b38 ^ (~b30 & b32); s[39] = b39 ^ (~b31 & b33); s[48] = b48 ^ (~b40 & b42); s[49] = b49 ^ (~b41 & b43); s[0] ^= self.Hash.RC[n]; s[1] ^= self.Hash.RC[n + 1];
			}
		}
	};
	this.Hash.Keccak = function(bits, padding, outputBits) {
		this.blocks = [];
		this.s = [];
		this.padding = padding;
		this.outputBits = outputBits;
		this.reset = true;
		this.finalized = false;
		this.block = 0;
		this.start = 0;
		this.blockCount = (1600 - (bits << 1)) >> 5;
		this.byteCount = this.blockCount << 2;
		this.outputBlocks = outputBits >> 5;
		this.extraBytes = (outputBits & 31) >> 3;

		for (var i = 0; i < 50; ++i) {
			this.s[i] = 0;
		}
	}
	this.Hash.Keccak.prototype.update = function (message) {
		if (this.finalized) {
			throw new Error('finalize already called');
		}
		var notString, type = typeof message;
		if (type !== 'string') {
			if (type === 'object') {
				if (message === null) {
					throw new Error('input is invalid type');
				} else if (message.constructor === ArrayBuffer) {
					message = new Uint8Array(message);
				} else if (!Array.isArray(message)) {
					if (!ArrayBuffer.isView(message)) {
						throw new Error('input is invalid type');
					}
				}
			} else {
				throw new Error('input is invalid type');
			}
			notString = true;
		}
		var blocks = this.blocks, byteCount = this.byteCount, length = message.length,
		blockCount = this.blockCount, index = 0, s = this.s, i, code;

		while (index < length) {
			if (this.reset) {
				this.reset = false;
				blocks[0] = this.block;
				for (i = 1; i < blockCount + 1; ++i) {
					blocks[i] = 0;
				}
			}
			if (notString) {
				for (i = this.start; index < length && i < byteCount; ++index) {
					blocks[i >> 2] |= message[index] << self.Hash.SHIFT[i++ & 3];
				}
			} else {
				for (i = this.start; index < length && i < byteCount; ++index) {
					code = message.charCodeAt(index);
					if (code < 0x80) {
						blocks[i >> 2] |= code << self.Hash.SHIFT[i++ & 3];
					} else if (code < 0x800) {
						blocks[i >> 2] |= (0xc0 | (code >> 6)) << self.Hash.SHIFT[i++ & 3];
						blocks[i >> 2] |= (0x80 | (code & 0x3f)) << self.Hash.SHIFT[i++ & 3];
					} else if (code < 0xd800 || code >= 0xe000) {
						blocks[i >> 2] |= (0xe0 | (code >> 12)) << self.Hash.SHIFT[i++ & 3];
						blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << self.Hash.SHIFT[i++ & 3];
						blocks[i >> 2] |= (0x80 | (code & 0x3f)) << self.Hash.SHIFT[i++ & 3];
					} else {
						code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
						blocks[i >> 2] |= (0xf0 | (code >> 18)) << self.Hash.SHIFT[i++ & 3];
						blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << self.Hash.SHIFT[i++ & 3];
						blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << self.Hash.SHIFT[i++ & 3];
						blocks[i >> 2] |= (0x80 | (code & 0x3f)) << self.Hash.SHIFT[i++ & 3];
					}
				}
			}
			this.lastByteIndex = i;
			if (i >= byteCount) {
				this.start = i - byteCount;
				this.block = blocks[blockCount];
				for (i = 0; i < blockCount; ++i) {
					s[i] ^= blocks[i];
				}
				self.Hash.f(s);
				this.reset = true;
			} else {
				this.start = i;
			}
		}
		return this;
	};
	this.Hash.Keccak.prototype.finalize = function () {
		if (this.finalized) {
			return;
		}
		this.finalized = true;
		var blocks = this.blocks, i = this.lastByteIndex, blockCount = this.blockCount, s = this.s;
		blocks[i >> 2] |= this.padding[i & 3];
		if (this.lastByteIndex === this.byteCount) {
			blocks[0] = blocks[blockCount];
			for (i = 1; i < blockCount + 1; ++i) {
				blocks[i] = 0;
			}
		}
		blocks[blockCount - 1] |= 0x80000000;
		for (i = 0; i < blockCount; ++i) {
			s[i] ^= blocks[i];
		}
		self.Hash.f(s);
	};
	this.Hash.Keccak.prototype.arrayBuffer = function () {
		this.finalize();
		var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,
		extraBytes = this.extraBytes, i = 0, j = 0;
		var array = [], offset, block;
		while (j < outputBlocks) {
			for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
				offset = j << 2;
				block = s[i];
				array[offset] = block & 0xFF;
				array[offset + 1] = (block >> 8) & 0xFF;
				array[offset + 2] = (block >> 16) & 0xFF;
				array[offset + 3] = (block >> 24) & 0xFF;
			}
			if (j % blockCount === 0) {
				self.Hash.f(s);
			}
		}
		if (extraBytes) {
			offset = j << 2;
			block = s[i];
			array[offset] = block & 0xFF;
			if (extraBytes > 1) {
				array[offset + 1] = (block >> 8) & 0xFF;
			}
			if (extraBytes > 2) {
				array[offset + 2] = (block >> 16) & 0xFF;
			}
		}
		return new Uint8Array(array);
	};
	this.Hash.Keccak.prototype.encode = function (x, right) {
		var o = x & 255, n = 1;
		var bytes = [o];
		x = x >> 8;
		o = x & 255;
		while (o > 0) {
			bytes.unshift(o);
			x = x >> 8;
			o = x & 255;
			++n;
		}
		if (right) {
			bytes.push(n);
		} else {
			bytes.unshift(n);
		}
		this.update(bytes);
		return bytes.length;
	};
	this.Hash.Keccak.prototype.encodeString = function (str) {
		var notString, type = typeof str;
		if (type !== 'string') {
			if (type === 'object') {
				if (str === null) {
					throw new Error(INPUT_ERROR);
				} else if (str.constructor === ArrayBuffer) {
					str = new Uint8Array(str);
				} else if (!Array.isArray(str)) {
					if (!ArrayBuffer.isView(str)) {
						throw new Error(INPUT_ERROR);
					}
				}
			} else {
				throw new Error(INPUT_ERROR);
			}
			notString = true;
		}
		var bytes = 0, length = str.length;
		if (notString) {
			bytes = length;
		} else {
			for (var i = 0; i < str.length; ++i) {
				var code = str.charCodeAt(i);
				if (code < 0x80) {
					bytes += 1;
				} else if (code < 0x800) {
					bytes += 2;
				} else if (code < 0xd800 || code >= 0xe000) {
					bytes += 3;
				} else {
				code = 0x10000 + (((code & 0x3ff) << 10) | (str.charCodeAt(++i) & 0x3ff));
				bytes += 4;
				}
			}
		}
		bytes += this.encode(bytes * 8);
		this.update(str);
		return bytes;
	};
	this.Keccak256 = function(msg) {
		var hash = new self.Hash.Keccak(256, [1, 256, 65536, 16777216], 256);
		return hash.update(msg).arrayBuffer();
	}
	this.Keccak384 = function(msg) {
		var hash = new self.Hash.Keccak(384, [1, 256, 65536, 16777216], 384);
		return hash.update(msg).arrayBuffer();
	}
	this.secp256k1Curve = new self.ECurve(0n,7n,0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn);
	this.secp256k1 = new self.PublicCurve(this.secp256k1Curve,[0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n],0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n);
	this.secp256k1.setSignHashFunction(this.Keccak256);
	this.secp384r1Curve = new self.ECurve(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffcn,0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn);
	this.secp384r1 = new self.PublicCurve(this.secp384r1Curve,[0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn],0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n);
	this.secp384r1.setSignHashFunction(this.Keccak384);
}
if (typeof window === 'undefined') {
	module.exports = Crypt;
}