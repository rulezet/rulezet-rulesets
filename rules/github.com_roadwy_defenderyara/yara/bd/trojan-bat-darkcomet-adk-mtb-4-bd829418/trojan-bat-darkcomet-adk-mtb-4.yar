rule Trojan_BAT_DarkComet_ADK_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 1f 26 9c 11 05 17 20 dc 00 00 00 9c 11 05 18 20 ff 00 00 00 9c 11 05 19 16 9c 11 05 1a 20 ad 00 00 00 9c 11 05 1b } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}