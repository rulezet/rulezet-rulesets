rule Trojan_BAT_Lokibot_RPR_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 00 20 01 00 fe 04 13 05 11 05 2d a9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}