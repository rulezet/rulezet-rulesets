rule Trojan_BAT_AgentTesla_RT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_02_0 = {06 07 9a 0c 08 28 ?? ?? ?? 0a 0d 09 72 ?? ?? ?? 70 72 ?? ?? ?? 70 17 15 16 28 ?? ?? ?? 0a 0d 02 6f ?? ?? ?? 06 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a } 		$a_81_1 = {58 4f 52 5f 44 65 63 72 79 70 74 } 		$a_81_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } 		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } 	condition:
		((#a_02_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=8
 
}