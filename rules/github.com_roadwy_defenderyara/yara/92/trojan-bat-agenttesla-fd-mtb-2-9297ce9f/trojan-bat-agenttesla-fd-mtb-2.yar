rule Trojan_BAT_AgentTesla_FD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 34 36 2e 32 32 30 2e 36 35 2f 6c 65 65 2f 43 68 64 63 65 73 70 62 6b 61 68 2e 6a 70 65 67 } 		$a_81_1 = {48 6f 6f 78 74 6c 6d 76 73 6e 66 } 		$a_81_2 = {44 6e 76 65 67 77 77 6f 68 6a 2e 41 75 70 7a 69 6b 6f 78 7a 69 6f 77 76 66 73 6b 6e 66 62 77 69 7a 71 77 } 		$a_81_3 = {50 78 6f 6e 71 67 74 68 78 62 62 73 63 69 6e 75 77 68 65 77 6a 75 77 75 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}