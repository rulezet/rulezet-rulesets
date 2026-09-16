rule Trojan_BAT_AgentTesla_EK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 07 11 05 11 07 1b 8d 01 00 00 01 13 0a 11 0a 16 72 ?? ?? ?? 70 28 07 00 00 06 a2 11 0a 17 1f 40 8c 07 00 00 01 a2 11 0a 18 11 07 17 } 		$a_03_1 = {11 07 6f 1c 00 00 0a 18 59 6f 1b 00 00 0a 28 06 00 00 06 a2 11 0a 19 1f 40 8c 07 00 00 01 a2 11 0a 1a 72 ?? ?? ?? 70 28 07 00 00 06 a2 11 0a 28 1d 00 00 0a 6f 1e 00 00 0a 13 05 11 05 1f 22 28 01 00 00 2b 3a 64 ff ff ff } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}