rule Trojan_BAT_DarkComet_ADK_MTB_16{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0d 13 0a 2b 56 11 09 17 d6 20 00 01 00 00 5d 13 09 07 11 05 11 09 91 d6 20 00 01 00 00 5d 0b 11 05 11 09 91 13 04 11 05 11 09 11 05 07 91 9c 11 05 07 11 04 9c 11 05 11 09 91 11 05 07 91 d6 20 00 01 00 00 5d 0c 02 50 11 0a 02 50 11 0a 91 11 05 08 91 61 9c 11 0a 17 d6 13 0a 11 0a 11 0d 31 a4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}