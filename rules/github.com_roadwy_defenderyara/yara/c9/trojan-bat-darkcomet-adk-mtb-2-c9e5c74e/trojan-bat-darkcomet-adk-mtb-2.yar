rule Trojan_BAT_DarkComet_ADK_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 1d 16 0c 2b 0f 02 07 02 07 91 06 08 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 eb 07 17 58 0b 07 02 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}