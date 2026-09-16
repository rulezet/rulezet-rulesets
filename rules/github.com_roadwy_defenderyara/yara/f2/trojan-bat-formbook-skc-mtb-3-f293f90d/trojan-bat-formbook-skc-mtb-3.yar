rule Trojan_BAT_FormBook_SKC_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.SKC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 11 06 11 07 91 6f 74 00 00 0a 00 00 11 07 17 58 13 07 11 07 09 fe 04 13 08 11 08 2d e1 } 		$a_01_1 = {00 02 06 07 6f 71 00 00 0a 0c 04 03 6f 72 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}