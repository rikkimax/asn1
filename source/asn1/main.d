module asn1.main;

import asn1.parser;
import asn1.generator.defs;
import asn1.encoder.ber.base;

void main() {
	//const auto data = test!("Test DEFINITIONS ::= BEGIN END\nByesies DEFINITIONS ::= BEGIN END");
	//pragma(msg, data.protocols[0].name);
	//pragma(msg, data.protocols[1].name);
	//auto data = test!(import("asn1Coding_test.asn"));
	//EncodedData d;
	//encodeType(d, 0);
	
	//auto data = test!(import("ldap.asn"));
	//import std.file;
	//write("out.txt", data.output());
	//outputASN1StructureFileToFile!"ldap.asn"("out2.d");
}

pure ASN1ParserData test(string text)() {
	ASN1ParserData data = ASN1ParserData(text);
	executeASN1Parser(data);
	return data;
}

//mixin ASN1StructureFile!"ldap.asn";
mixin ASN1StructureFile!"ldap.asn";