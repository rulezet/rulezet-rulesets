rule Trojan_BAT_DarkComet_ADK_MTB_7{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 21 02 50 06 02 50 06 91 7e 01 00 00 04 06 7e 01 00 00 04 8e 69 5d 91 61 28 ?? ?? ?? 0a 9c 06 17 58 0a 06 02 50 8e 69 32 d8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}