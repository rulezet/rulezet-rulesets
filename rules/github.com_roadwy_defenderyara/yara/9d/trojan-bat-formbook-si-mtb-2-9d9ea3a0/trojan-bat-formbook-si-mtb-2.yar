rule Trojan_BAT_FormBook_SI_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 0a 02 6f 1d 00 00 0a 3c 0a 01 00 00 11 0b 02 6f 1e 00 00 0a 32 0b 11 0a 17 58 13 0a 16 13 0b 2b de 07 6f 32 00 00 0a 06 3c e9 00 00 00 02 11 0a 11 0b 6f } 		$a_81_1 = {50 53 5f 54 69 6d 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 		$a_81_2 = {24 34 34 35 66 64 34 39 32 2d 33 37 34 36 2d 34 64 61 34 2d 61 34 62 35 2d 30 36 38 39 63 62 66 34 34 66 39 62 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}