rule Trojan_BAT_FormBook_AF_MTB_12{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 2b 16 09 11 04 08 11 04 9a 1f 10 28 a3 00 00 0a 9c 11 04 17 d6 13 04 00 11 04 20 00 c2 00 00 fe 04 13 06 11 06 2d db } 		$a_01_1 = {50 00 6f 00 6b 00 65 00 6d 00 6f 00 6e 00 53 00 79 00 73 00 74 00 65 00 6d 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}