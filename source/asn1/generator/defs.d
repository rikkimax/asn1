module asn1.generator.defs;
import asn1.parser.defs;

mixin template ASN1StructureFile(string file) {
	mixin ASN1Structure!(import(file));
}

mixin template ASN1Structure(string text) {
	import asn1.generator.generator;
	mixin(getStruct(ASN1ParserData.parse(text)));
}