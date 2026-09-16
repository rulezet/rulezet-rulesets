rule Trojan_BAT_LokiBot_RPH_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d b8 06 17 58 0a 00 09 17 58 0d 09 20 00 ?? 01 00 fe 04 13 06 11 06 2d 9b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}