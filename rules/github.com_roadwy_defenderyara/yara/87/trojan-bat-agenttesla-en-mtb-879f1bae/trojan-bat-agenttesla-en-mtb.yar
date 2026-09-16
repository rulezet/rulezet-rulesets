rule Trojan_BAT_AgentTesla_EN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 04 07 ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? 6a 61 b7 28 } 		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_2 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}