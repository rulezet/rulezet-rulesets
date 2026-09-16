rule is__hex_top_mandibule64 {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$hex01 = { 48 8D 05 43 01 00 00 48 89 E7 FF D0 } 		$hex02 = { 53 48 83 EC 50 48 89 7C 24 08 48 8B 44 24 08 } 		$hex03 = { 48 81 EC 18 02 00 00 89 7C 24 1C 48 89 74 } 		$hex04 = { 53 48 81 EC 70 01 01 00 48 89 7C 24 08 48 8D 44 24 20 48 05 00 00 } 	condition:
                3 of them 
}