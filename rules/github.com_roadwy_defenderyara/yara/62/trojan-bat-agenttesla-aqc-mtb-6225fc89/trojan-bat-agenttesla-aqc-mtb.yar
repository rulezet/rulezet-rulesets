rule Trojan_BAT_AgentTesla_AQC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 11 04 06 07 ?? ?? ?? ?? ?? 13 05 11 05 ?? ?? ?? ?? ?? 13 06 09 08 11 06 b4 9c 07 17 d6 0b 07 16 31 de 08 17 d6 0c 06 17 d6 0a 06 } 		$a_02_1 = {25 16 09 a2 25 17 ?? ?? ?? ?? ?? a2 25 13 04 14 14 18 ?? ?? ?? ?? ?? 25 16 17 9c 25 13 05 17 ?? ?? ?? ?? ?? 26 11 05 16 91 2d 02 } 	condition:
		((#a_03_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}