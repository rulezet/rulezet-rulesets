rule Trojan_BAT_DarkComet_ADK_MTB_13{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0d 09 0e 04 2f 03 09 10 04 16 0a 2b 0e 05 06 d3 18 5a 58 08 06 93 53 06 17 58 0a 06 0e 04 32 ed } 		$a_01_1 = {16 0a 2b 0b 07 06 03 06 58 47 9c 06 17 58 0a 06 04 32 f1 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}