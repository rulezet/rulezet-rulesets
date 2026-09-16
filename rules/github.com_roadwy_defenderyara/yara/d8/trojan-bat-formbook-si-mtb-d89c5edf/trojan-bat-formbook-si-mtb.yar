rule Trojan_BAT_FormBook_SI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 11 13 02 6f 85 00 00 0a fe 04 16 fe 01 13 2a 11 2a 2c 05 38 fd 00 00 00 11 14 02 6f 86 00 00 0a fe 04 16 fe 01 13 2b 11 2b 2c 0f 00 11 13 17 58 13 13 16 13 14 38 d6 00 00 00 06 6f a9 00 00 0a 03 fe 04 16 fe 01 13 2c 11 2c 2c 05 38 c4 00 00 00 02 11 13 11 14 6f aa 00 00 0a } 		$a_81_1 = {4a 75 65 67 6f 4d 65 6d 6f 72 69 61 43 6f 6c 6f 72 65 73 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}