module asn1.parser.handler;
import asn1.parser.defs;
import std.string : splitLines, strip, indexOf;
import std.conv : to;

pure void executeASN1Parser(ref ASN1ParserData data) {
	size_t stage;
	size_t subStage;
	size_t protocolNum;
	
	ASN1ProtocolDefinition currentDef;
	size_t braceIn;
	bool increasedBrace;
	
	foreach(line; data.text.splitLines()) {
		line = line.strip();
		string[] lineA = line.split(" ", "\t").notEmptyElements().notCommentedElements();
		
		void removeFirstLineA() {
			if (lineA.length > 1)
				lineA = lineA[1 .. $];
			else
				lineA = [];
		}
		
		void incrementProtocolCount() {
			protocolNum++;
			data.protocols ~= new ASN1ProtocolData;
			if (data.protocols.length == 1)
				protocolNum = 0;
		}
		
		void incrementChildDefinitionCount() {
			ASN1ProtocolDefinition ncurrentDef = new ASN1ProtocolDefinition;
			
			data.protocols[protocolNum].definitions ~= ncurrentDef;
			
			currentDef = ncurrentDef;
		}
		
		void incrementSiblingDefinitionCount() {
			ASN1ProtocolDefinition ncurrentDef = new ASN1ProtocolDefinition;
			
			if (!increasedBrace && currentDef.parentDef !is null) {
				currentDef.parentDef.subDefs ~= ncurrentDef;
				ncurrentDef.parentDef = currentDef.parentDef;
			} else {
				currentDef.subDefs ~= ncurrentDef;
				ncurrentDef.parentDef = currentDef;
			}
			
			currentDef = ncurrentDef;
		}
		
		void decrementSubDefinitionCount() {
			if (currentDef.parentDef !is null)
				currentDef = currentDef.parentDef;
		}
		
		void handleDefType() {
			
			// EncodingPrefix
			if (lineA[0][0] == '[') {
				string prefix = lineA[0][1 .. $];
				foreach(s; lineA[1 .. $]) {
					removeFirstLineA();
					if (s[$-1] == ']') {
						prefix ~= " " ~ s[0 .. $-1];
						break;
					}
					prefix ~= " " ~ s;
				}
				
				currentDef.encodingPrefix = prefix;
			}
			
			bool repeat;
			do {
				if (repeat)
					repeat = false;
				
				assert(lineA.length > 0);
				switch (lineA[0]) {
					case "SEQUENCE":
						currentDef.type = ASN1DefinitionType.Sequence;
						if (lineA.length > 1) {
							if (lineA[1] == "OF") {
								currentDef.type = ASN1DefinitionType.SequenceOf;
								repeat = true;
								removeFirstLineA();
							}
						}
						break;
					case "ENUMERATED":
						currentDef.type = ASN1DefinitionType.Enumerated;
						break;
					case "SET": 
						currentDef.type = ASN1DefinitionType.Set;
						if (lineA.length > 1) {
							if (lineA[1] == "OF") {
								currentDef.type = ASN1DefinitionType.SetOf;
								repeat = true;
								removeFirstLineA();
							}
						}
						break;
					case "CHOICE": 
						currentDef.type = ASN1DefinitionType.Choice;
						break;
					case "OCTET":
						if (lineA.length > 1) {
							if (lineA[1] == "STRING") {
								removeFirstLineA();
								currentDef.nameOfType = "OCTET STRING";
								currentDef.type = ASN1DefinitionType.TypeAssignment;
							}
						}
						break;
					default:
						if (lineA[0][$-1] == ',')
							lineA[0].length--;
						
						bool defaultHandler = true;
						if (currentDef.parentDef !is null) {
							if (currentDef.parentDef.type == ASN1DefinitionType.Enumerated) {
								if (lineA[0].length > 1) {
									if (lineA[0][0] == '(' && lineA[0][$-1] == ')') {
										currentDef.value = lineA[0][1 .. $-1];
										defaultHandler = false;
									}
								}
							}
						}
						
						if (defaultHandler)
							currentDef.nameOfType = lineA[0];
						
						if (currentDef.type != ASN1DefinitionType.SequenceOf &&
						    currentDef.type != ASN1DefinitionType.SetOf)
							currentDef.type = ASN1DefinitionType.TypeAssignment;
						break;
				}
				
				removeFirstLineA();
			} while(repeat);
			
			if (lineA.length > 0) {
				string t;
				if (lineA[0][$-1] == ',') t = lineA[0][0 .. $-1];
				else t = lineA[0];
				
				switch(t) {
					case "OPTIONAL":
						currentDef.presenceConstraint = ASN1PresenceConstraint.Optional;
						removeFirstLineA();
						break;
					case "PRESENT":
						currentDef.presenceConstraint = ASN1PresenceConstraint.Optional;
						removeFirstLineA();
						break;
					case "ABSENT":
						currentDef.presenceConstraint = ASN1PresenceConstraint.Optional;
						removeFirstLineA();
						break;
					default:
						break;
				}
			}
		}
		
		// ModuleIdentifier
		if (stage == 0) {
			if (lineA.length > 0) {
				incrementProtocolCount();
				
				data.protocols[protocolNum].name = lineA[0];
				
				removeFirstLineA();
				stage++;
			}
		}
		
		//DEFINITIONS
		if (stage == 1) {
			if (lineA.length > 0) {
				if (lineA[0] == "DEFINITIONS") {
					removeFirstLineA();
					stage++;
				}
			}
		}
		
		// modifiers on a definition of a protocol
		if (stage == 2) {
			// request both its value and the keyword INSTRUCTIONS on same line
			// (look ahead issue)
			if (lineA.length >= 2) {
				if (lineA[1] == "INSTRUCTIONS") {
					removeFirstLineA();
					data.protocols[protocolNum].encodingreference = lineA[0];
					removeFirstLineA();
				}
			}
			
			// TagDefault
			// required to be on one line. (look ahead issue).
			if (lineA.length >= 2) {
				if (lineA[0 .. 2] == ["EXPLICIT", "TAGS"]) {
					removeFirstLineA();
					removeFirstLineA();
					data.protocols[protocolNum].tagDefault = TagDefaultOption.Explicit;
				} else if (lineA[0 .. 2] == ["IMPLICIT", "TAGS"]) {
					removeFirstLineA();
					removeFirstLineA();
					data.protocols[protocolNum].tagDefault = TagDefaultOption.Implicit;
				} else if (lineA[0 .. 2] == ["AUTOMATIC", "TAGS"]) {
					removeFirstLineA();
					removeFirstLineA();
					data.protocols[protocolNum].tagDefault = TagDefaultOption.Automatic;
				}
			}
			
			// ExtensionDefault
			// required to be on one line. (look ahead issue).
			if (lineA.length >= 2) {
				if (lineA[0 .. 2] == ["EXPLICIT", "TAGS"]) {
					removeFirstLineA();
					removeFirstLineA();
					data.protocols[protocolNum].extensibilityImplied = true;
				}
			}
			
			// finish off definition
			if (lineA.length > 0) {
				if (lineA[0] == "::=") {
					removeFirstLineA();
					stage++;
				}
			}
		}
		
		// begin of a protocol definition
		if (stage == 3) {
			if (lineA.length > 0) {
				if (lineA[0] == "BEGIN") {
					removeFirstLineA();
					stage++;
				}
			}
		}
		
		// end of a protocol definition
		if (stage > 3) {
			if (lineA.length > 0) {
				if (lineA[0] == "END") {
					removeFirstLineA();
					// reset it to stage one.
					// that way if there is more protocols it can handle it
					stage = 0;
					subStage = 0;
				}
			}
		}
		
		// ModuleBody
		if (stage == 4) {
			
			// head stuff of a declaration
			if (subStage == 0) {
				// Exports
				
				// Imports
				
				subStage++;
			}
			
			bool repeat = false;
			bool hitSecondChildFirst = false;
			
			do {
				if (repeat)
					repeat = false;
				
				if (subStage == 1 || subStage == 2) {
					if (lineA.length > 4) {
						if (lineA[1] == "::=") {
							// Range value
							if (lineA[3][0] == '(') {
								incrementChildDefinitionCount();
								currentDef.type = ASN1DefinitionType.RangeValueAssignment;
								currentDef.name = lineA[0];
								currentDef.nameOfType = lineA[2];
								
								string a = lineA[3][1 .. $];
								size_t gotten;
								
								foreach(l; lineA[4 .. $]) {
									gotten++;
									if (l[$-1] == ')') {
										a ~= " " ~ l[0 .. $-1];
										break;
									}
									a ~= " " ~ l;
								}
								
								lineA.length -= gotten;
								
								string[] aS = a.split(" ");
								if (aS.length == 1) aS = a.split("..");
								else if (aS.length >= 3) aS = [aS[0], aS[2]];
								else assert(0);
								
								currentDef.valueRangeMin = aS[0];
								currentDef.valueRangeMax = aS[1];
							}
						}
					}
					
					if (lineA.length > 3) {
						if (lineA[2] == "::=") {
							// ValueAssignment
							
							incrementChildDefinitionCount();
							currentDef.type = ASN1DefinitionType.ValueAssignment;
							currentDef.name = lineA[0];
							currentDef.nameOfType = lineA[1];
							currentDef.value = lineA[3];
							
							removeFirstLineA();
							removeFirstLineA();
							removeFirstLineA();
							removeFirstLineA();
						} 
					}
					
					if (lineA.length > 1) {
						// AssignmentList
						
						if (lineA[1] == "::=") {
							incrementChildDefinitionCount();
							currentDef.name = lineA[0];
							
							removeFirstLineA();
							removeFirstLineA();
							
							handleDefType();
							subStage = 2;
							
							braceIn = 0;
							if (lineA.length > 0) {
								if (lineA[0][0] == '{') {
									braceIn = 1;
									removeFirstLineA();
								}
							}
							
						}
					}
				}
				
				if (subStage == 2) {
					// TypeAssignment
					if (lineA.length > 1) {
						incrementSiblingDefinitionCount();
						increasedBrace = false;
						
						currentDef.name = lineA[0];
						
						removeFirstLineA();
						handleDefType();
					}
					
					if (lineA.length > 0) {
						if (lineA[0][0] == '{') {
							braceIn++;
							increasedBrace = true;
						} else if (lineA[0][0] == '}') {
							braceIn--;
							removeFirstLineA();
							decrementSubDefinitionCount();
							if (braceIn == 0) {
								subStage--;
							} else {
								repeat = true;
							}
						}
					}
				}
				
			} while(repeat);
		}
		
		// EncodingControlSections
		if (stage == 5) {
			// right now I have NO IDEA how to implement this!
			// no examples and not very clearly documented
		}
	}
}

private {
	pure string[] split(string text, string[] delimaters...) {
		string[] ret;
		ptrdiff_t i;
		while((i = min(text.indexOfs(delimaters))) >= 0) {
			ret ~= text[0 .. i];
			text = text[i + lengthOfIndex(text, i, delimaters) .. $];
		}
		if (text.length > 0) {
			ret ~= text;	
		}
		return ret;
	}
	
	unittest {
		assert(test.split("|") == ["abcd", "efgh", "ijkl"]);
		string test2 = "abcd||efgh||ijkl";
		assert(test2.split("||") == ["abcd", "efgh", "ijkl"]);
	}
	
	pure string[] notEmptyElements(string[] elements) {
		string[] ret;
		
		foreach(e; elements) {
			if (e != "")
				ret ~= e;
		}
		
		return ret;
	}
	
	pure string[] notCommentedElements(string[] elements) {
		string[] ret;
		
		foreach(e; elements) {
			if (e == "--")
				return ret;
			ret ~= e;
		}
		
		return ret;
	}
	
	pure size_t[] indexOfs(string text, string[] delimiters) {
		size_t[] ret;
		
		foreach(delimiter; delimiters) {
			ret ~= text.indexOf(delimiter);
		}
		
		return ret;
	}
	
	pure size_t lengthOfIndex(string text, size_t index, string[] delimiters) {
		foreach(delimiter; delimiters) {
			if (text.indexOf(delimiter) == index) return delimiter.length;
		}
		assert(0);
	}
	
	pure size_t min(size_t[] nums...) {
		size_t ret = size_t.max;
		
		foreach(i; nums) {
			if (i < ret) {
				ret = i;
			}
		}
		
		return ret;
	}
}