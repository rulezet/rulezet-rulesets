rule Trojan_BAT_DarkComet_ADK_MTB_9{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 25 08 09 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 1f 67 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 07 17 d6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}