module asn1.encoder.ber.defs;
import asn1.encoder.ber.base2;
import asn1.parser.defs;
import std.traits : isSomeString;

enum ASN1ConstructedType {
	Unknown,
	Sequence,
	Set
}

/**
 * Turns an ASN1EncodeClassTag into a ubyte that has bits 7/8 encoded.
 */
pure ubyte classTagEncodeValue(ASN1EncodeClassTag tag) {
	switch(tag) {
		case ASN1EncodeClassTag.Application:
			return (1 << 6) | (0 << 7);
			
		case ASN1EncodeClassTag.Context_Specific:
			return (0 << 6) | (1 << 7);
			
		case ASN1EncodeClassTag.Private:
			return (1 << 6) | (1 << 7);
			
		case ASN1EncodeClassTag.Universal:
		default:
			return (0 << 6) | (0 << 7);
	}
}

/**
 * Holds a message that has been encoded.
 */
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

/**
 * Encodes a peice of data into an EncodedData struct instance.
 * 
 * To support sets it is required to know the encoded class and id.
 * 	Only class is needed for sequence
 * 	This can be acomplished by UDA's
 * 
 * See_Also:
 * 		EncodedData
 * 		valueGetBytes
 */
pure void encodeType(T)(ref EncodedData parent, T t) {
	EncodedData data;
	
	ubyte tag;
	
	static if (__traits(isIntegral, T)) {
		// INTEGER
		tag = 2;
		
		enum constructed = false;
		enum indefinate = false;
	} else static if (isSomeString!T || is(T == ubyte[]) || is(T == byte[])) {
		// OCTET STRING
		tag = 4;
		
		enum constructed = false;
		enum indefinate = false;
	} else static if (is(T == ASN1NullType)) {
		// NULL 
		tag = 5;
		
		enum constructed = false;
		enum indefinate = false;
	} else static if (is(T == class) || is(T == struct)) {
		// UDA check ASN1ConstructedType.SEQUENCE
		
		// 	SEQUENCE / SEQUENCE OF
		tag = 16;
		
		// UDA check ASN1ConstructedType.SET
		
		// 	SET / SET OF
		tag = 17;
		
		enum constructed = true;
		enum indefinate = true;
	}
	
	if (!indefinate) {
		data.identity ~= tag;
		data.content = valueGetBytes(t);
		data.length = valueGetBytes(data.content.length);
	} else static if (constructed) {
		// identity handling.
		
		
		// TODO: this is where we need to do some trait magic...
		foreach(p; __traits(allMembers, T)) {
			// make sure its not a method.
			// only a property that has the ASN1Property annotation.
		}
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