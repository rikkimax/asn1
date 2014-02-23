module asn1.encoder.ber.base;
import std.math : ceil;

enum BitEighthCount = 1 + (1f / 8f);

struct EncodedData {
	ubyte[] identity;
	ubyte[] length;
	ubyte[] content;
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

void encodeIdentity(ref EncodedData data, ClassTag type, bool constructed, size_t tagNumber) {
	ubyte[size_t.sizeof] tagValue;
	
	version(LittleEndian) {
		tagValue = tagNumber.reverseEndianess();
	} else version(BigEndian) {
		tagValue = *cast(ubyte[size_t.sizeof]*)&tagNumber;
	} else {
		static assert(0, "What me no likey, platform endianess");
	}
	
	data.identity.length = 1;
	
	data.identity[0] |= cast(ubyte)type; // class
	data.identity[0] |= (cast(ubyte)constructed) << 2; // primitive/constructed
	
	size_t aBitsLength; // highest bit that is set upon tagNumber
	for (size_t i = 0; i < tagNumber.sizeof * 8; i++) {
		if (tagNumber & (1 << i)) {
			aBitsLength = i;
		}
	}
	
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
				
				iIndex++;
				bIndex++;
				
				if (i + 8 >= aLength) {
					// last byte
					data.identity[iIndex] |= 0 << 7;
				} else {
					// not last byte
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

pure ubyte[size_t.sizeof] reverseEndianess(size_t value) {
	ubyte[size_t.sizeof] ret;
	
	size_t iRet;
	
	for (size_t i; i < size_t.sizeof * 8; i++) {
		size_t j = (size_t.sizeof * 8) - i;
		
		ret[iRet] |= (value & (1 << i)) << j;
		
		if ((i & 8) == 7) {
			iRet++;	
		}
	}
	
	return ret;
}