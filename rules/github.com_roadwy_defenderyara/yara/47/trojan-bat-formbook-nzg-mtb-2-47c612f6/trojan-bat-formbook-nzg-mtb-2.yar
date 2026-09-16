rule Trojan_BAT_FormBook_NZG_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {65 32 61 61 37 32 39 65 2d 36 35 37 34 2d 34 62 64 66 2d 61 37 61 36 2d 65 30 64 62 63 38 30 38 35 32 36 62 } 		$a_01_1 = {00 03 4b 0a 03 04 4b 54 04 06 54 } 		$a_01_2 = {91 11 07 11 10 95 61 } 		$a_81_3 = {73 65 6e 64 42 75 74 74 6f 6e } 		$a_81_4 = {50 41 53 53 57 4f 52 44 } 	condition:
		((#a_81_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}