rule Trojan_BAT_LokiBot_ALB_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.ALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 15 00 07 11 07 07 11 07 94 03 5a 1f 64 5d 9e 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } 		$a_01_1 = {53 74 75 64 65 6e 74 5f 48 6f 75 73 69 6e 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}