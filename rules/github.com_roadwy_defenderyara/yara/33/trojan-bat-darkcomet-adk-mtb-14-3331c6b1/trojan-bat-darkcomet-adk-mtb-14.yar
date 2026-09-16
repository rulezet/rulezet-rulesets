rule Trojan_BAT_DarkComet_ADK_MTB_14{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 16 13 06 2b 5d 11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}