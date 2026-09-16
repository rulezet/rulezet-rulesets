rule Trojan_BAT_AgentTesla_RPD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {32 00 2e 00 35 00 38 00 2e 00 31 00 34 00 39 00 2e 00 32 00 2f 00 [0-40] 2e 00 6a 00 70 00 67 00 } 		$a_01_1 = {54 6f 41 72 72 61 79 } 		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 } 		$a_01_3 = {47 65 74 54 79 70 65 } 		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}