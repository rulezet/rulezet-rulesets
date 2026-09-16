rule Trojan_BAT_LokiBot_RPM_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1b 59 1c 58 0d 09 17 fe 04 13 09 11 09 2d c3 06 17 58 0a 00 08 1a 59 1b 58 0c 08 20 00 c6 00 00 fe 04 13 0a 11 0a 2d a5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}