rule Trojan_BAT_AgentTesla_BAS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {11 04 02 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 11 05 17 8d ?? ?? ?? 01 25 16 02 28 ?? ?? ?? 06 a2 6f } 		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 64 6c 6c } 		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } 		$a_81_3 = {47 65 74 54 79 70 65 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}