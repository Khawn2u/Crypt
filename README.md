# Crypt

# Create new crypt
var crypt = new Crypt();

# crypt.ECurve
This is a constructor that creates a new Eliptic Curve with paramiters a, b, and modulo m.

# crypt.Keccak256
This is the Keccak256 hash of the input, the input can be text or a Uint8Array.

# crypt.Keccak384
This is the Keccak384 hash of the input, the input can be text or a Uint8Array.

# crypt.PublicCurve
This is a constructor taking in as the first paramiter a crypt.ECurve object, second paramiter an array of BigInt with length 2 as a generator point, and as the third paramiter the order of the generator point on the curve difined in the first paramiter.

# crypt.secp256k1
This is a pre-made crypt.PublicCurve Object with already diffined paramiters, following the secp256k1 curve documentation.

# crypt.secp384r1
This is a pre-made crypt.PublicCurve Object with already diffined paramiters, following the secp384r1 curve documentation.
