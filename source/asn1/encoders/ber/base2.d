module asn1.encoder.ber.base2;
import asn1.generator.defs;
import binary.pack;
import std.traits : isSomeString;

/**
 * Gets the byte values of a type instance.
 * 
 * Types supported:
 * 		- string
 * 		- byte[]
 * 		- ubyte[]
 * 		- int
 *      - uint
 *      - long
 *      - ulong
 *      - ubyte
 *      - byte
 * 
 * What isn't supported:
 * 		- BIT STRING
 * 		- OBJECT IDENTIFIER
 * 		- SEQUENCE
 * 		- SEQUENCE OF
 * 		- SET
 * 		- SET OF
 * 		- PrintableString
 * 		- T61String
 * 		- IA5String
 * 		- UTCTime
 */
pure ubyte[] valueGetBytes(T)(T t) {
	static if (isSomeString!T || is(T == ubyte[]) || is(T == byte[])) {
		ubyte[] ret;
		foreach(c; t) {
			ret ~= pack!(">c")(c);
		}
		return ret;
	} else static if (is(T == ASN1NullType)) {
		return [0];
	} else {
		ubyte[] ret;
		bool negative = t < 0;
		
		bool notMin = false;
		bool notMax = false;
		
		T tleft = t;
		
		foreach(b; pack!(">" ~ formatCharOf!T)(t)) {
			if (!notMin && b != 0) {
				notMin = true;
			}
			
			if (notMin) {
				if (negative) {
					
					if (!notMax && b != 255) {
						notMax = true;
					}
					
					if (notMax) {
						tleft += b;
						ret ~= b;
					}
					
				} else {
					if (b == 128) {
						ret ~= 0;
					}
					ret ~= b;
				}
			}
		}
		
		if (negative) {
			if (tleft < 0 && tleft >= -128) {
				ret = [cast(ubyte)(tleft + 1)] ~ ret;
			}
		}
		
		if (ret.length == 0) ret ~= 0;
		
		return ret;
	}
}

unittest {
	assert(valueGetBytes(0) == [0x0]);
	assert(valueGetBytes(127) == [0x7F]);
	assert(valueGetBytes(128) == [0x0, 0x80]);
	assert(valueGetBytes(256) == [0x1, 0x0]);
	assert(valueGetBytes(257) == [0x1, 0x1]); // I think this is a correct value.
	assert(valueGetBytes(-128) == [0x80]);
	assert(valueGetBytes(-129) == [0xFF, 0x7F]);
	
	assert(valueGetBytes(ulong.max) == [255, 255, 255, 255, 255, 255, 255, 255]); // another I think should work fine
	
	assert(valueGetBytes(ASN1NullType()) == [0x0]);
	
	assert(valueGetBytes("\x01\x23\x45\x67\x89\xab\xcd\xef") == [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
	assert(valueGetBytes(cast(byte[])[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]) == [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
	assert(valueGetBytes(cast(ubyte[])[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]) == [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
}