rule Trojan_BAT_DarkComet_ADK_MTB_15{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 d1 0d 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e b7 fe 04 13 04 11 04 2d c9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}