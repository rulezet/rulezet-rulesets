rule Win_Trojan_Small_191
{
strings:
	$a0 = { 8ec3bfa002faa674134e4fb14cf3a4be84005626a526a55fb02aabab5f8d754cb9b2fe0e07f3a4c380fc40751c80 }


condition:
	$a0
}