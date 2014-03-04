module asn1.generator.generator;
import asn1.parser.defs;
import std.string : tr, toLower;
import std.conv : to;

pure string getStruct(ASN1ParserData data, size_t tabbed = 0) {
	string ret;
	
	foreach(p; data.protocols) {
		ret ~= getIndent(tabbed) ~ "struct " ~ p.name.tr("-", "_") ~ " {\n";
		
		foreach(def; p.definitions) {
			ret ~= getDefinitionStruct(DefsPass(data, def, tabbed + 1));
		}
		
		ret ~= getIndent(tabbed) ~ "}\n";
	}
	
	return ret;
}

struct DefsPass {
	ASN1ParserData data;
	ASN1ProtocolDefinition def;
	size_t tabbed;
	
	bool generateProperties;
	bool choice;
	size_t choiceVal;
}

pure string getDefinitionStruct(DefsPass pass) {
	string ret;
	switch (pass.def.type) {
		case ASN1DefinitionType.Sequence:
			ret ~= getIndent(pass.tabbed) ~ "struct " ~ pass.def.name.tr("-", "_") ~ " {\n";
			size_t indent = pass.tabbed + 1;
			
			foreach(def2; pass.def.subDefs) {
				ret ~= getDefinitionStruct(DefsPass(pass.data, def2, indent));
			}
			
			ret ~= getIndent(pass.tabbed) ~ "}\n";
			break;
			
		case ASN1DefinitionType.Choice:
			ret ~= getIndent(pass.tabbed) ~ "struct " ~ pass.def.name.tr("-", "_") ~ " {\n";
			ret ~= getIndent(pass.tabbed + 1) ~ "size_t choice;\n";
			
			size_t indent = pass.tabbed + 1;
			size_t choiceVal = 1; // size_t.init == 0 so is null
			
			foreach(def2; pass.def.subDefs) {
				ret ~= getDefinitionStruct(DefsPass(pass.data, def2, indent, true, true, choiceVal));
				choiceVal++;
			}
			
			ret ~= getIndent(pass.tabbed) ~ "}\n";
			break;
			
		case ASN1DefinitionType.TypeAssignment:
			switch(pass.def.nameOfType.toLower()) {
				case "integer":
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ "int _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property int " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ((pass.choice ? "; choice = " ~ to!string(pass.choiceVal) : "" )) ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(int value) {return _" ~ pass.def.name.tr("-", "_") ~ " = value;}\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "int " ~ pass.def.name.tr("-", "_") ~ ";\n";
					break;
				case "octet string":
					ret ~= getIndent(pass.tabbed) ~ "struct " ~ pass.def.name.tr("-", "_") ~ " {\n";
					
					ret ~= getIndent(pass.tabbed + 1) ~ "int value;\n";
					ret ~= getIndent(pass.tabbed + 1) ~ "alias value this;\n";
					
					// TODO invariants
					
					ret ~= getIndent(pass.tabbed) ~ "}\n";
					break;
				default:
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ pass.def.nameOfType ~ " " ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property " ~ pass.def.nameOfType ~ " " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(" ~ pass.def.nameOfType ~ " value) {return _" ~ pass.def.name.tr("-", "_") ~ " = value" ~ ((pass.choice ? "; choice = " ~ to!string(pass.choiceVal) : "" )) ~ ";}\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ pass.def.nameOfType ~ " " ~ pass.def.name.tr("-", "_") ~ ";\n";
					break;
			}
			break;
			
		case ASN1DefinitionType.RangeValueAssignment:
			switch(pass.def.nameOfType.toLower()) {
				case "integer":
					ret ~= getIndent(pass.tabbed) ~ "struct " ~ pass.def.name.tr("-", "_") ~ " {\n";
					
					ret ~= getIndent(pass.tabbed + 1) ~ "int value;\n";
					ret ~= getIndent(pass.tabbed + 1) ~ "alias value this;\n";
					
					// TODO invariants
					
					ret ~= getIndent(pass.tabbed) ~ "}\n";
					break;
				default:
					break;
			}
			break;
			
		default:
			break;
	}
	return ret;
}