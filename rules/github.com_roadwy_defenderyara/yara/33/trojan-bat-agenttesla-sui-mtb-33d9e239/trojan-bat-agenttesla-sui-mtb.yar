rule Trojan_BAT_AgentTesla_SUI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {3a 2f 2f 31 30 33 2e 37 34 2e 31 30 35 2e 37 38 2f 47 52 41 4e 41 44 41 2f 5a 6e 75 73 6c 2e 76 64 66 } 		$a_81_1 = {47 65 74 42 79 74 65 73 } 		$a_81_2 = {43 6f 6e 76 65 72 74 } 		$a_81_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}