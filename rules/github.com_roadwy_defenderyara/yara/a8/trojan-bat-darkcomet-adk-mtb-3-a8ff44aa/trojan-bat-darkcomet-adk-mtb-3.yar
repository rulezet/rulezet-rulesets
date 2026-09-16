rule Trojan_BAT_DarkComet_ADK_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 1f 06 08 8f 0c 00 00 01 25 71 0c 00 00 01 07 08 07 8e 69 5d 91 61 d2 81 0c 00 00 01 08 17 58 0c 08 06 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}