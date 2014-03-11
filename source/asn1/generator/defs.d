module asn1.generator.defs;
import asn1.parser.defs;
import asn1.generator.generator;
import std.file;

struct ASN1NullType {}

mixin template ASN1StructureFile(string file) {
	mixin ASN1Structure!(import(file));
}

mixin template ASN1Structure(string text) {
	import asn1.generator.generator;
	
	static if (!__traits(compiles, {ASN1NullType type;})) {
		public import asn1.generator.defs : ASN1NullType;
	}
	mixin(getStruct(ASN1ParserData.parse(text)));
}

void outputASN1StructureFileToFile(string file)(string ofile) {
	write(ofile, getStruct(ASN1ParserData.parse(import(file))));
}

void outputASN1StructureToFile(string text)(string ofile) {
	write(ofile, getStruct(ASN1ParserData.parse(text)));
}