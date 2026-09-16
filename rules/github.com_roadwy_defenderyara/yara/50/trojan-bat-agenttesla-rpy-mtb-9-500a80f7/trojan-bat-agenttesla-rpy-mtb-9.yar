rule Trojan_BAT_AgentTesla_RPY_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {16 0b 2b 22 11 04 06 07 28 bb 00 00 06 13 05 11 05 28 e0 00 00 0a 13 06 09 08 11 06 28 e1 00 00 0a 9c 07 17 58 0b 07 17 fe 04 13 07 11 07 2d d4 } 		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } 		$a_01_2 = {54 6f 57 69 6e 33 32 } 		$a_01_3 = {54 6f 42 79 74 65 } 		$a_01_4 = {43 6f 6e 76 65 72 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}