rule Trojan_BAT_RedLineStealer_AD_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1a 58 19 5d 13 1d 19 8d ?? 00 00 01 13 1e 11 1e 16 12 17 28 ?? 00 00 0a 9c 11 1e 17 12 17 28 ?? 00 00 0a 9c 11 1e 18 12 17 28 ?? 00 00 0a 9c 11 19 16 fe 02 13 21 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}