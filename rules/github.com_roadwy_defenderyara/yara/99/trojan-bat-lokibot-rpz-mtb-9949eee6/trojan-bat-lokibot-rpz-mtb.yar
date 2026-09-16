rule Trojan_BAT_LokiBot_RPZ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 11 04 28 91 00 00 0a 11 06 28 91 00 00 0a da 04 d6 1f 1a 5d 13 07 07 11 06 28 91 00 00 0a 11 07 d6 28 92 00 00 0a 28 93 00 00 0a 28 94 00 00 0a 0b 00 2b 10 00 07 11 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}