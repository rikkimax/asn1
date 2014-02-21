module asn1.parser.defs;
import asn1.parser.handler;
import std.conv : to;

mixin template ParseASN1File(string file) {
	mixin ParseASN1Text!(import(file));
}

mixin template ParseASN1Text(string text) {
	
}

enum TagDefaultOption {
	Explicit,
	Implicit,
	Automatic,
	Empty
}

struct ASN1ParserData {
	string text;
	ASN1ProtocolData[] protocols;
	
	string output(size_t indent=0) {
		string ret;
		ret ~= getIndent(indent) ~ "[";
		//ret ~= text ~ ", "; // seperated out so can remove Huge text from debug message.
		ret ~= "[\r\n";
		foreach (p; protocols) {
			ret ~= p.output(indent + 1) ~ ", \r\n";
		}
		
		if (ret[$-4] == ',') {
			ret.length -= 4;
			ret ~= "\r\n";
		}
		
		ret ~= getIndent(indent) ~ "]]";
		return ret;
	}
}

class ASN1ProtocolData {
	string name;
	string encodingreference;
	TagDefaultOption tagDefault;
	bool extensibilityImplied;
	
	ASN1ProtocolDefinition[] definitions;
	
	string output(size_t indent=0) {
		string ret;
		ret ~= getIndent(indent) ~ "[" ~ name ~ ", " ~ to!string(encodingreference) ~ ", " ~ to!string(tagDefault) ~ ", " ~ to!string(extensibilityImplied) ~ ", [\r\n";
		foreach (d; definitions) {
			ret ~= d.output(indent + 1) ~ ", \r\n";
		}
		
		if (ret[$-4] == ',') {
			ret.length -= 4;
			ret ~= "\r\n";
		}
		
		ret ~= getIndent(indent) ~ "]]";
		return ret;
	}
}

enum ASN1DefinitionType {
	Unknown,
	Sequence,
	Choice,
	TypeAssignment,
	ValueAssignment,
	RangeValueAssignment,
	SequenceOf,
	Set,
	SetOf,
	Enumerated
}

enum ASN1PresenceConstraint {
	Unknown,
	Absent,
	Prsent,
	Optional
}

class ASN1ProtocolDefinition {
	string name;
	string nameOfType;
	ASN1DefinitionType type;
	string value;
	
	string valueRangeMin;
	string valueRangeMax;
	
	string encodingPrefix;
	ASN1PresenceConstraint presenceConstraint;
	
	ASN1ProtocolDefinition parentDef;
	ASN1ProtocolDefinition[] subDefs;
	
	string output(size_t indent=0) {
		string ret;
		ret ~= getIndent(indent) ~ "[" ~ to!string(type) ~ ", " ~ name ~ ", " ~ nameOfType ~ ", " ~ value ~ ", " ~
			valueRangeMin ~ ", " ~ valueRangeMax ~ ", " ~ encodingPrefix ~ ", " ~ to!string(presenceConstraint) ~ ", [\r\n";
		
		foreach (d; subDefs) {
			ret ~= d.output(indent + 1) ~ ", \r\n";
		}
		
		if (ret[$-4] == ',') {
			ret.length -= 4;
			ret ~= "\r\n";
		}
		
		ret ~= getIndent(indent) ~ "]]";
		return ret;
	}
}

string getIndent(size_t size) {
	string ret;
	
	for (size_t i=0; i < size; i++) {
		ret ~= "    ";
	}
	
	return ret;
}