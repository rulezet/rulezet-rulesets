rule Trojan_BAT_FormBook_SK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 95 00 00 00 5a 11 0e 1a 63 61 61 13 0e 1f 55 13 38 38 13 f3 ff ff 16 13 2c 11 39 20 c8 00 00 00 93 20 de 77 00 00 59 13 38 38 fb f2 ff ff 02 11 2b 11 2c 20 f4 03 00 00 20 eb 03 00 00 28 2d 00 00 2b 13 2d 04 03 6f a4 00 00 0a 59 } 		$a_81_1 = {53 6f 6c 61 72 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}