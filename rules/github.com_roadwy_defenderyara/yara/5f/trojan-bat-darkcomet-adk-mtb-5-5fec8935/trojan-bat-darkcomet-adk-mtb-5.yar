rule Trojan_BAT_DarkComet_ADK_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 19 02 06 02 06 91 03 06 7e ?? 00 00 04 5d 91 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 e1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}