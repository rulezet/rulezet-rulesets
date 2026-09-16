rule Trojan_BAT_LokiBot_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f 82 00 00 0a 13 0a 07 12 0a 28 83 00 00 0a 6f 84 00 00 0a 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}