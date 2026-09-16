rule Trojan_BAT_DarkComet_ADM_MTB_8{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2c 02 2b 4b 7e ?? 00 00 0a 72 ?? 00 00 70 17 6f ?? 00 00 0a 0c 08 72 ?? 00 00 70 72 ?? 00 00 70 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 14 0b 2b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}