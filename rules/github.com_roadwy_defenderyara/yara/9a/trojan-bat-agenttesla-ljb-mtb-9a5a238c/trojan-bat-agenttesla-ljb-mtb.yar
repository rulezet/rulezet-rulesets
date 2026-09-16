rule Trojan_BAT_AgentTesla_LJB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4c 32 33 64 33 32 64 4c 78 64 6d 23 64 65 64 6d 32 33 } 		$a_81_1 = {4c 4b 73 6e 7a 45 4c 4b 73 6e 7a 6e 4c 4b 73 6e 7a 74 72 79 50 4c 4b 73 6e 7a 6f 69 4c 4b 73 6e 7a 6e 4c 4b 73 6e 7a 74 } 		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } 		$a_01_3 = {52 65 70 6c 61 63 65 } 		$a_01_4 = {47 65 74 50 72 6f 70 65 72 74 79 } 		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}