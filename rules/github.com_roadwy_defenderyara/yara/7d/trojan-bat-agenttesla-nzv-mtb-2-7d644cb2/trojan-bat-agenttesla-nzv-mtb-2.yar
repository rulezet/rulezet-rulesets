rule Trojan_BAT_AgentTesla_NZV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {56 4f 4f 4f 4f 30 31 } 		$a_81_1 = {56 4f 4f 4f 4f 30 33 } 		$a_81_2 = {43 00 6f 00 6e 00 74 00 72 00 00 0d 6f 00 6c 00 5f 00 52 00 75 00 6e } 		$a_81_3 = {49 00 6e 00 00 05 76 00 6f 00 00 05 6b 00 65 } 		$a_81_4 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } 		$a_81_5 = {53 74 72 52 65 76 65 72 73 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}