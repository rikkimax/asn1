import asn1.parser;

void main() {
	//const auto data = test!("Test DEFINITIONS ::= BEGIN END\nByesies DEFINITIONS ::= BEGIN END");
	//pragma(msg, data.protocols[0].name);
	//pragma(msg, data.protocols[1].name);
	//auto data = test!(import("asn1Coding_test.asn"));
	auto data = test!(import("ldap.asn"));
	import std.file;
	write("out.txt", data.output());
}

pure ASN1ParserData test(string text)() {
	ASN1ParserData data = ASN1ParserData(text);
	executeASN1Parser(data);
	return data;
}