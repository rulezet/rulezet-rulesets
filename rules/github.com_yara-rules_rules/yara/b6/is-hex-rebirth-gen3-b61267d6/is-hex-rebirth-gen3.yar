rule is__hex_Rebirth_gen3 {
	meta:
		author = "unixfreaxjp"
		date = "2018-01-21"
	strings:
		$hex01 = { 0D C0 A0 E1 00 D8 2D E9 }
		$hex02 = { 3C 1C 00 06 27 9C 97 98 }
		$hex03 = { 94 21 EF 80 7C 08 02 A6 }
		$hex04 = { E6 2F 22 4F 76 91 18 3F }
		$hex05 = { 06 00 1C 3C 20 98 9C 27 }
		$hex06 = { 55 89 E5 81 EC ?? 10 00 }
		$hex07 = { 55 48 89 E5 48 81 EC 90 }
		$hex08 = { 6F 67 69 6E 00 }
	condition:
        	2 of them 
}