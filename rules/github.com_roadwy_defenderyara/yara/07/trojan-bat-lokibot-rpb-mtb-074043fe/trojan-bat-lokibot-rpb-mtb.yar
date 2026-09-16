rule Trojan_BAT_LokiBot_RPB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 11 07 07 11 07 9a 1f 10 28 b2 00 00 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } 		$a_01_1 = {4d 00 61 00 67 00 69 00 63 00 55 00 49 00 2e 00 47 00 52 00 45 00 45 00 4e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}