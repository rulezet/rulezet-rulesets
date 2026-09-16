rule Trojan_BAT_DarkComet_ADM_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 0d 2b 52 72 ?? ?? ?? 70 02 09 18 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 03 08 6f ?? 00 00 0a 28 ?? 00 00 0a 6a 61 69 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 06 11 04 6f ?? 00 00 0a 26 08 03 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}