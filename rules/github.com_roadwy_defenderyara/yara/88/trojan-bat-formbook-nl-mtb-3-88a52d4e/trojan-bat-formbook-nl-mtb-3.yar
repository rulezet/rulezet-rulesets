rule Trojan_BAT_FormBook_NL_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 5e 45 04 00 00 00 32 00 00 00 02 00 00 00 dc ff ff ff 1d 00 00 00 2b 30 02 02 7b 41 00 00 04 28 a3 00 00 06 06 20 6f 2c ad 05 5a 20 33 be 5e 53 61 2b c4 } 		$a_01_1 = {20 b5 88 b2 41 61 25 0d 1a 5e 45 04 00 00 00 37 00 00 00 02 00 00 00 1f 00 00 00 dc ff ff ff 2b 35 07 08 30 08 20 16 b9 65 13 25 2b 06 20 fc 1f 01 55 25 26 09 20 ff 4e 0a 0b 5a 61 2b c2 06 16 07 28 6a 04 00 06 0a 09 20 46 7d 3d 58 5a 20 99 34 c6 7b 61 2b aa } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}