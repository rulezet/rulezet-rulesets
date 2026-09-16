rule Trojan_BAT_AgentTesla_AYL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 0c 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 06 09 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 0a 13 04 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08 13 05 2b } 		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } 		$a_80_2 = {47 65 74 54 79 70 65 } 		$a_80_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}