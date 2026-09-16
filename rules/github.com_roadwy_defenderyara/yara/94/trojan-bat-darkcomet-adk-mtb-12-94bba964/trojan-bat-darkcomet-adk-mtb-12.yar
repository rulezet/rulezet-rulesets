rule Trojan_BAT_DarkComet_ADK_MTB_12{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 31 02 08 8f 11 00 00 01 25 71 11 00 00 01 07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 11 00 00 01 08 17 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}