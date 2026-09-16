rule Trojan_BAT_AgentTesla_NT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {7e 19 00 00 0a 8c ?? ?? ?? 1b 2d 0a 28 ?? ?? ?? 2b 80 ?? ?? ?? 0a } 		$a_01_1 = {53 65 74 50 72 6f 6a 65 63 74 45 72 72 6f 72 } 		$a_01_2 = {43 6c 65 61 72 50 72 6f 6a 65 63 74 45 72 72 6f 72 } 		$a_01_3 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } 		$a_01_4 = {44 41 54 41 43 45 4e 54 45 52 45 4e 43 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}