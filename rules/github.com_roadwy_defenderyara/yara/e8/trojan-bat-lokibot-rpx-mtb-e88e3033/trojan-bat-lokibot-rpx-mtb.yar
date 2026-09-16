rule Trojan_BAT_LokiBot_RPX_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 0e 04 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}