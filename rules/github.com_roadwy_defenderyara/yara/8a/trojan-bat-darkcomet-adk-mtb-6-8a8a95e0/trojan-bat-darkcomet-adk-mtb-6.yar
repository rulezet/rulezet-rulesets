rule Trojan_BAT_DarkComet_ADK_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 03 8e b7 17 da 13 04 0d 2b 24 03 09 03 09 91 ?? ?? ?? 8e b7 5d 91 09 06 d6 07 8e b7 d6 1d 5f 64 d2 20 ff 00 00 00 5f b4 61 9c 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}