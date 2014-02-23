module asn1.generator.generator;
import asn1.parser.defs;
import std.string : tr;

pure string getStruct(ASN1ParserData data) {
	string ret;
	
	foreach(p; data.protocols) {
		ret ~= "struct " ~ p.name.tr("-", "_") ~ " {\n";
		ret ~= "}\n";
	}
	
	return ret;
}