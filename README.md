# Crypt

# Create new crypt
var crypt = new Crypt();

# crypt.ECurve
This is a constructor that creates a new Eliptic Curve with paramiters a, b, and modulo m

# crypt.Keccak256
This is the Keccak256 hash of the input, the inout can be text or a Uint8Array

# crypt.PublicCurve
This is a constructor taking in as the first paramiter a crypt.ECurve object, second paramiter an array of BigInt with length 2 as a generator point, and as the third paramiter the order of the generator point on the curve difined in the first paramiter
