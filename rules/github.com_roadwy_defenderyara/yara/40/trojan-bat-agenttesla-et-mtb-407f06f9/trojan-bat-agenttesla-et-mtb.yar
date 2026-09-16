rule Trojan_BAT_AgentTesla_ET_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 03 11 05 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 00 1f fb 13 07 } 		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_2 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}