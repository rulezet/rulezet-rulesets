rule is__hex_mid_mandibule32 {
	meta:
		author = "unixfreaxjp"
		date = "2018-06-01"
	strings:
		$hex05 = { E8 09 07 00 00 81 C1 FC 1F 00 00 8D 81 26 E1 FF FF } 		$hex06 = { 56 53 83 EC 24 E8 E1 05 00 00 81 C3 D0 1E 00 00 8B 44 24 30} 		$hex07 = { 81 C3 E8 29 00 00 C7 44 24 0C } 		$hex08 = { E8 C6 D5 FF FF 83 C4 0C 68 00 01 00 00 } 	condition:
                3 of them 
}