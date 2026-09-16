rule Trojan_BAT_AgentTesla_EAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 5c 9d 6f ?? 00 00 0a 25 8e 69 18 59 0b 07 9a 0a de 03 26 de 00 06 2a } 		$a_03_1 = {16 0a 2b 36 7e ?? 00 00 04 06 7e ?? 00 00 04 06 9a 1b 28 } 		$a_03_2 = {0a a2 06 17 58 0a 06 7e ?? 00 00 04 8e 69 32 c0 } 		$a_01_3 = {52 65 70 6c 61 63 65 } 		$a_01_4 = {53 70 6c 69 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}