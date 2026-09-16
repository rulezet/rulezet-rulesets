rule Trojan_BAT_AgentTesla_AGT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 09 11 05 6f ?? ?? ?? 0a 13 06 04 09 11 05 6f ?? ?? ?? 0a 13 07 11 07 28 ?? ?? ?? 0a 13 08 07 06 11 08 28 ?? ?? ?? 0a 9c 11 05 17 d6 13 05 11 05 11 04 31 cb } 		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_80_2 = {47 65 74 54 79 70 65 } 		$a_80_3 = {52 65 76 65 72 73 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}