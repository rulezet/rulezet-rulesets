rule Trojan_BAT_Njrat_RPY_MTB{
	meta:
		description = "Trojan:BAT/Njrat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 6f 24 00 00 9d 06 1a 20 f7 29 00 00 9d 06 16 20 79 1b 00 00 9d 06 1d 20 18 0f 00 00 9d 06 17 20 d0 2b 00 00 9d 06 19 20 59 3f 00 00 9d 06 1b 20 ab 38 00 00 9d 06 1c 20 c9 04 00 00 9d 20 be 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}