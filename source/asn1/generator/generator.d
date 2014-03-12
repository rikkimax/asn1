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
	bool generateEnumValue;
}

/**
 * Creates a string which comprises of a definition.
 * 
 * TODO:
 * 		- Implement @ASN1ConstructedTypeUDA(ASN1ConstructedType.SEQUENCE/SET/SEQUENCE_OF/SET_OF)
 * 		- Implement @ASN1EncodedUDA(size_t order[, ASN1EncodeClassTag. ...])
 */
pure string getDefinitionStruct(DefsPass pass) {
	string ret;
	
	switch(pass.def.name.toLower()) {
		case "module":
			goto case "append_";
		case "version":
			goto case "append_";
		case "scope":
			goto case "append_";
		case "final":
			goto case "append_";
		case "delete":
			goto case "append_";
			
		case "append_":
			pass.def.name ~= "_";
			break;
		default:
			break;
	}
	
	switch (pass.def.type) {
		case ASN1DefinitionType.Sequence:
			ret ~= getIndent(pass.tabbed) ~ "class " ~ pass.def.name.tr("-", "_") ~ " {\n";
			size_t indent = pass.tabbed + 1;
			
			foreach(def2; pass.def.subDefs) {
				ret ~= getDefinitionStruct(DefsPass(pass.data, def2, indent));
			}
			
			ret ~= getIndent(pass.tabbed) ~ "}\n";
			break;
			
		case ASN1DefinitionType.Choice:
			ret ~= getIndent(pass.tabbed) ~ "class " ~ pass.def.name.tr("-", "_") ~ " {\n";
			ret ~= getIndent(pass.tabbed + 1) ~ "size_t choice;\n";
			
			size_t indent = pass.tabbed + 1;
			size_t choiceVal = 1; // size_t.init == 0 so is null
			
			foreach(def2; pass.def.subDefs) {
				ret ~= getDefinitionStruct(DefsPass(pass.data, def2, indent, true, true, choiceVal));
				choiceVal++;
			}
			
			ret ~= getIndent(pass.tabbed) ~ "}\n";
			
			ret ~= "\n";
			break;
			
		case ASN1DefinitionType.Enumerated:
			ret ~= getIndent(pass.tabbed) ~ "enum _" ~ pass.def.name.tr("-", "_") ~ " {\n";
			size_t indent = pass.tabbed + 1;
			
			foreach(def2; pass.def.subDefs) {
				ret ~= getDefinitionStruct(DefsPass(pass.data, def2, indent, false, false, 0, true));
			}
			
			ret ~= getIndent(pass.tabbed) ~ "}\n";
			ret ~= getIndent(pass.tabbed) ~ "_" ~ pass.def.name.tr("-", "_") ~ " " ~ pass.def.name.tr("-", "_") ~ ";\n";
			
			ret ~= "\n";
			break;
			
		case ASN1DefinitionType.TypeAssignment:
			switch(pass.def.nameOfType.toLower()) {
				case "integer":
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ "size_t _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property size_t " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(size_t value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = int;\n";
					break;
					
				case "octet string":
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ "string _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property string " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(string value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = string;\n";
					break;
					
				case "boolean":
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ "bool _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property bool " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(bool value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = bool;\n";
					break;
					
				case "null":
					ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = ASN1NullType;\n";
					break;
					
				default:
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ pass.def.nameOfType ~ " _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property " ~ pass.def.nameOfType ~ " " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(" ~ pass.def.nameOfType ~ " value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = " ~ pass.def.nameOfType ~ ";\n";
					break;
			}
			if (pass.generateProperties)
				ret ~= "\n";
			break;
			
		case ASN1DefinitionType.RangeValueAssignment:
			switch(pass.def.nameOfType.toLower()) {
				case "integer":
					ret ~= getIndent(pass.tabbed) ~ "struct " ~ pass.def.name.tr("-", "_") ~ " {\n";
					
					ret ~= getIndent(pass.tabbed + 1) ~ "size_t value;\n";
					ret ~= getIndent(pass.tabbed + 1) ~ "alias value this;\n";
					
					ret ~= getIndent(pass.tabbed + 1) ~ "invariant() {\n";
					
					ret ~= getIndent(pass.tabbed + 2) ~ "assert(value >= " ~ pass.def.valueRangeMin ~ ");\n";
					ret ~= getIndent(pass.tabbed + 2) ~ "assert(value < " ~ pass.def.valueRangeMax ~ ");\n";
					
					ret ~= getIndent(pass.tabbed + 1) ~ "}\n";
					
					ret ~= getIndent(pass.tabbed) ~ "}\n";
					break;
				default:
					break;
			}
			ret ~= "\n";
			break;
			
		case ASN1DefinitionType.PropertyAssignment:
			switch(pass.def.nameOfType.toLower()) {
				case "integer":
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ "size_t _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property size_t " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(size_t value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
					} else if (pass.generateEnumValue) {
						if (pass.def.value == "")
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ ",\n";
						else
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ " = " ~ pass.def.value ~ ",\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "size_t " ~ pass.def.name.tr("-", "_") ~ ";\n";
					break;
					
				case "octet string":
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ "string _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property string " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(string value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
					} else if (pass.generateEnumValue) {
						if (pass.def.value == "")
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ ",\n";
						else
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ " = " ~ pass.def.value ~ ",\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "string " ~ pass.def.name.tr("-", "_") ~ ";\n";
					break;
					
				case "boolean":
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ "bool _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "@property bool " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(bool value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
					} else if (pass.generateEnumValue) {
						if (pass.def.value == "")
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ ",\n";
						else
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ " = " ~ pass.def.value ~ ",\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ "bool " ~ pass.def.name.tr("-", "_") ~ ";\n";
					break;
					
				default:
					if (pass.generateProperties) {
						ret ~= getIndent(pass.tabbed) ~ pass.def.nameOfType ~ " _" ~ pass.def.name.tr("-", "_") ~ ";\n";
						ret ~= getIndent(pass.tabbed) ~ "static if (is(" ~ pass.def.nameOfType ~ " : ASN1NullType)) {\n";
						
						ret ~= getIndent(pass.tabbed + 1) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "() {" ~ ((pass.choice ? " choice = 0;" : "" )) ~ "}\n";
						
						ret ~= getIndent(pass.tabbed) ~ "} else {\n";
						
						ret ~= getIndent(pass.tabbed + 1) ~ "@property " ~ pass.def.nameOfType ~ " " ~ pass.def.name.tr("-", "_") ~ "() {return _" ~ pass.def.name.tr("-", "_") ~ ";}\n";
						ret ~= getIndent(pass.tabbed + 1) ~ "@property void " ~ pass.def.name.tr("-", "_") ~ "(" ~ pass.def.nameOfType ~ " value) {_" ~ pass.def.name.tr("-", "_") ~ " = value;" ~ ((pass.choice ? " choice = " ~ to!string(pass.choiceVal) ~ ";" : "" )) ~ "}\n";
						
						ret ~= getIndent(pass.tabbed) ~ "}\n";
					} else if (pass.generateEnumValue) {
						if (pass.def.value == "")
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ ",\n";
						else
							ret ~= getIndent(pass.tabbed) ~ pass.def.name.tr("-", "_") ~ " = " ~ pass.def.value ~ ",\n";
					} else
						ret ~= getIndent(pass.tabbed) ~ pass.def.nameOfType ~ " " ~ pass.def.name.tr("-", "_") ~ ";\n";
					break;
			}
			break;
			
		case ASN1DefinitionType.ValueAssignment:
			switch(pass.def.nameOfType.toLower()) {
				case "integer":
					ret ~= getIndent(pass.tabbed) ~ "enum size_t " ~ pass.def.name.tr("-", "_") ~ " = " ~ pass.def.value ~ ";\n";
					break;
					
				case "octet string":
					// TODO do we need to escape the value?
					ret ~= getIndent(pass.tabbed) ~ "enum string " ~ pass.def.name.tr("-", "_") ~ " = \"" ~ pass.def.value ~ "\";\n";
					break;
					
				default:
					break;
			}
			break;
			
		case ASN1DefinitionType.SequenceOf:
			goto case ASN1DefinitionType.SetOf;
			
		case ASN1DefinitionType.SetOf:
			switch(pass.def.nameOfType.toLower()) {
				case "integer":
					ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = int[];\n";
					break;
					
				case "octet string":
					ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = string[];\n";
					break;
					
				default:
					ret ~= getIndent(pass.tabbed) ~ "alias " ~ pass.def.name.tr("-", "_") ~ " = " ~ pass.def.nameOfType ~ "[];\n";
					break;
			}
			break;
			
		default:
			break;
	}
	return ret;
}