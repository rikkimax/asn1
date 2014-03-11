module asn1.encoder.ber.base;
import asn1.generator.defs;
import std.math : ceil;
import std.algorithm : reverse;
import std.bitmanip : nativeToBigEndian;
import std.traits : isBasicType, isSomeString;
import std.conv : to;
import binary.pack;

enum BitEighthCount = 1 + (1f / 8f);

struct EncodedData {
	ubyte[] identity;
	ubyte[] length;
	ubyte[] content;
	
	/**
	 * Encoded data is not required to work on a end message.
	 * It can be used for raw value encoding.
	 */
	void opOpAssign(string op)(EncodedData data) {
		static if (op == "~") {
			content ~= data.identity;
			content ~= data.length;
			content ~= data.content;
		}
	}
}

version(LittleEndian) {
	enum ClassTag : ubyte {
		Universal = 0,
		Application = (1 << 1),
		Context_Specific = (1 << 0),
		Private = (1 << 0) | (1 << 1)
	}
} else version(BigEndian) {
	enum ClassTag : ubyte {
		Universal = 0,
		Application = (1 << 6),
		Context_Specific = (1 << 7),
		Private = (1 << 7) | (1 << 6)
	}
}

pure void encodeIdentity(ref EncodedData data, ClassTag type, bool constructed, size_t tagNumber) {
	ubyte[size_t.sizeof] tagValue = nativeToBigEndian(tagNumber);
	
	data.identity.length = 1;
	
	data.identity[0] |= cast(ubyte)type; // class
	data.identity[0] |= (cast(ubyte)constructed) << 2; // primitive/constructed
	
	size_t aBitsLength = highestOrderOfSetBit(tagNumber); // highest bit that is set upon tagNumber
	
	// tag number
	if (aBitsLength > 5) {
		// hey new octets!
		
		data.identity ~= tagValue;
		
		// make the 0 .. 5 bits 1
		for (size_t i; i < 5; i++) {
			data.identity[0] |= 1 << i;
		}
		
		// set the new size of the identity
		size_t aLength = cast(size_t)ceil(aBitsLength * BitEighthCount);
		data.identity.length = aLength + 1;
		
		size_t iIndex = 1;
		size_t bIndex = 0;
		
		for (size_t i; i < aBitsLength; i++) {
			data.identity[iIndex] |= cast(ubyte)((tagValue[bIndex] & (1 << i)) << 7 - i);
			
			if (i % 8 == 7) {
				// we finished this byte
				
				if (i + 1 < aBitsLength) {
					// make sure that we are only doing this for every but the last byte.
					
					iIndex++;
					bIndex++;
					
					data.identity[iIndex] |= 1 << 7;
				}
			}
		}
		
	} else {
		// no extra octets
		
		for (size_t i; i < 5; i++) {
			data.identity[0] |= cast(ubyte)((tagValue[0] & (1 << i)) << 7 - i);
		}
		return;
	}
}

/**
 * Encodes a primitive.
 * 
 * TODO:
 * 		BIT STRING
 * 		OBJECT IDENTIFIER
 * 		SET / SET OF (encode order)
 * 		PrintableString
 * 		T61String
 * 		IA5String
 * 		UTCTime
 * 
 * 		Non primitive types, data values appended
 */
pure void encodeType(T)(ref EncodedData parent, T t) {
	EncodedData data;
	
	ubyte tag;
	ubyte[] content;
	
	size_t bits;
	bool indefinate = false;
	bool primitive = true;
	
	static if (__traits(isIntegral, T)) {
		// INTEGER
		tag = 2;
		bits = T.sizeof * 8;
		
		content = to!(ubyte[])(contentGetValue(t));
	} else static if (is(T == string)) {
		// OCTET STRING
		tag = 4;
		bits = T.length * 8;
		content = cast(byte[])nativeToBigEndian(t);
	} else static if (is(T == ASN1NullType)) {
		// NULL 
		tag = 5;
		bits = 0;
	} else static if (is(T == class) || is(T == struct)) {
		// SEQUENCE / SEQUENCE OF
		tag = 16;
		indefinate = true;
		primitive = false;
	}
	
	data.identity ~= tag;
	
	if (!indefinate) {
		data.content = cast(ubyte[])zeroOutButLast(content, false, t < 0);
		data.length = cast(ubyte[])zeroOutButLast(data.content.length);
	} else {
		// TODO: this is where we need to do some trait magic...
	}
	
	if (indefinate) {
		data.content ~= [00, 00];
	}
	
	parent ~= data;
}

unittest {
	EncodedData iData;
	
	iData = EncodedData();
	encodeType(iData, 0);
	assert(iData.content == [0x02, 0x01, 0x0]);
	
	iData = EncodedData();
	encodeType(iData, 127);
	assert(iData.content == [0x02, 0x01, 0x7F]);
	
	iData = EncodedData();
	encodeType(iData, 128);
	assert(iData.content == [0x02, 0x02, 0x0, 0x80]);
	
	iData = EncodedData();
	encodeType(iData, 256);
	assert(iData.content == [0x02, 0x02, 0x1, 0x0]);
	
	iData = EncodedData();
	encodeType(iData, -128);
	assert(iData.content == [0x02, 0x01, 0x80]);
	
	iData = EncodedData();
	encodeType(iData, -129);
	assert(iData.content == [0x02, 0x02, 0xFF, 0x7F]);
}

pure size_t highestOrderOfSetBit(T)(T value) {
	size_t ret;
	for (size_t i = 0; i < value.sizeof * 8; i++) {
		if ((value & (1 << i)) == (1 << i)) {
			ret = i;
		}
	}
	return ret;
}

pure size_t highestOrderOfSetByte(T)(T value) {
	return (highestOrderOfSetBit(value) / 8) + 1;
}

pure ubyte[] zeroOutButLast(T)(T value) {
	return zeroOutButLast(*cast(ubyte[T.sizeof]*)&value);
}

pure ubyte[] zeroOutButLast(ubyte[] value, bool removeExcess = true, bool negative = false) {
	ubyte[] ret;
	
	if (value.length == 1 && value[0] <= byte.max && value[0] >= 0) {
		ret.length = 1;
		ret[0] = value[0];
	} else if (negative) {
		// we don't need to do anything special
		// which is weird
		ret = value;
	} else {
		size_t i;
		size_t bi;
		size_t bu;
		
		foreach(k, b; value) {
			for (size_t j = 0; j < 8; j++) {
				if (i == 0) {
					if (ret.length > 0) {
						if (cast(ubyte)ret[$-1] == 128) {
							ret ~= ret[$-1];
							ret[$-2] = 0;
							bu++;
						}
					}
					ret.length++;
				}
				
				if (b & (1 << j)) {
					ret[$-1] |=  1 << i;
					bu = k + 1;
				}
				
				if (i % 8 == 6 && k + 1 < value.length) {
					i = 0;
				} else {
					i++;
				}
			}
		}
		
		if (ret.length > 0) {
			if (cast(ubyte)ret[$-1] == 128) {
				ret ~= ret[$-1];
				ret[$-2] = 0;
				bu++;
			}
		}
		
		if (removeExcess) {
			ret = ret[0 .. bu];
			reverse(ret);
		}
	}
	
	return ret;
}

pure ubyte[] contentGetValue(T)(T t) {
	static if (isSomeString!T) {
		ubyte[] ret;
		foreach(c; t) {
			ret ~= pack!(">c")(c);
		}
	} else {
		ubyte[] ret;
		
		bool notMin = false;
		bool notMax = false;
		
		T tleft = t;
		
		foreach(b; pack!(">" ~ formatCharOf!T)(t)) {
			if (!notMin && b != 0) {
				notMin = true;
			}
			
			if (notMin) {
				if (t < 0) {
					
					if (!notMax && b != 255) {
						notMax = true;
					}
					
					if (notMax) {
						tleft += b;
						ret ~= b;
					}
					
				} else {
					ret ~= b;
				}
			}
		}
		
		if (t < 0) {
			if (tleft < 0 && tleft >= -128) {
				ret = [cast(ubyte)(tleft + 1)] ~ ret;
			}
		}
		
		if (ret.length == 0) ret ~= 0;
		
		return ret;
	}
}