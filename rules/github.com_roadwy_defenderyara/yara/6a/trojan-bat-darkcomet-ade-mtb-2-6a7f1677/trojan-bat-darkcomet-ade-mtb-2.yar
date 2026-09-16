rule Trojan_BAT_DarkComet_ADE_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 20 17 19 15 28 ?? 00 00 0a 02 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 7d ?? 00 00 04 17 02 7c ?? 00 00 04 15 6a 16 28 ?? 00 00 0a 17 8d ?? 00 00 01 13 0b 11 0b 16 17 9e 11 0b 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}