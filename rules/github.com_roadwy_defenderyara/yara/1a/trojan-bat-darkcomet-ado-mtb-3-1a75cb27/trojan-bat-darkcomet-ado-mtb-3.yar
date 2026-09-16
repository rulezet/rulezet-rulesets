rule Trojan_BAT_DarkComet_ADO_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 13 05 16 0c 06 74 ?? 00 00 01 08 1f 64 d6 17 d6 8d ?? 00 00 01 28 ?? 00 00 0a 74 ?? 00 00 1b 0a 07 06 11 05 1f 64 6f ?? 00 00 0a 13 06 11 06 16 2e 0e 11 05 11 06 d6 13 05 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}