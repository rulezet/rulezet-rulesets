rule Trojan_BAT_LokiBot_RPS_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 ?? ?? ?? ?? ?? fe 04 13 05 11 05 2d a9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}