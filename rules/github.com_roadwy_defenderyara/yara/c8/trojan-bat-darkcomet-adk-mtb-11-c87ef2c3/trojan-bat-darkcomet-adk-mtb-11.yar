rule Trojan_BAT_DarkComet_ADK_MTB_11{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 20 19 15 15 28 ?? 00 00 0a 1f 0a 13 07 1b 07 15 6a 16 28 ?? 00 00 0a 1f 0b 13 07 17 8d ?? 00 00 01 13 04 11 04 16 1b 9e 11 04 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}