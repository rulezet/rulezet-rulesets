rule Trojan_BAT_DarkComet_ADK_MTB_10{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 02 8e b7 17 da 13 06 13 05 2b 29 09 11 05 02 11 05 91 11 04 61 08 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da 33 04 16 0b 2b 04 07 17 d6 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}