rule Trojan_BAT_AgentTesla_NZZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {20 20 20 50 69 40 73 2e 57 68 69 74 40 20 } 		$a_01_1 = {54 6f 42 79 74 65 } 		$a_01_2 = {52 65 70 6c 61 63 65 } 		$a_01_3 = {47 65 74 54 79 70 65 } 		$a_01_4 = {53 70 6c 69 74 } 	condition:
		((#a_81_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}