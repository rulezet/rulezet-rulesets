rule Trojan_BAT_FormBook_AF_MTB_15{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 1f 00 02 11 04 09 6f 09 00 00 0a 13 05 08 11 04 09 11 05 6f 10 00 00 0a 00 00 11 04 17 58 13 04 11 04 06 fe 04 13 06 11 06 2d d6 } 		$a_01_1 = {13 06 11 06 16 fe 02 13 07 11 07 2c 0f 00 11 05 11 04 16 11 06 6f 17 00 00 0a 00 00 00 11 06 16 fe 02 13 08 11 08 2d c9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}