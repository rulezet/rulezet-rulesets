rule Trojan_BAT_DarkComet_ADM_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 20 17 19 15 28 ?? 00 00 0a 1a 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0b 1b 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 13 05 1c 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 13 06 1d 13 0a 17 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}