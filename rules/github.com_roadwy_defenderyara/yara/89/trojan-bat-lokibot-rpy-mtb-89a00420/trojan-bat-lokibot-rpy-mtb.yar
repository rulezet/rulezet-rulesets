rule Trojan_BAT_LokiBot_RPY_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 91 11 08 61 07 11 06 17 58 08 5d 91 59 11 09 58 11 09 17 59 5f 13 0a 07 11 06 11 0a d2 9c 00 11 06 17 58 13 06 11 06 08 fe 04 13 0b 11 0b 2d a7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}