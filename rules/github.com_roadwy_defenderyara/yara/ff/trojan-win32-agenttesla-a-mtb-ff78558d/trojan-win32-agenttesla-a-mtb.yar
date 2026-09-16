rule Trojan_Win32_AgentTesla_A_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 6f 6f 74 5c 63 69 6d 76 32 } 		$a_81_1 = {55 73 65 72 6e 61 6d 65 3a } 		$a_81_2 = {50 61 73 73 77 6f 72 64 3a } 		$a_81_3 = {77 6f 72 6c 6f 72 64 65 72 62 69 6c 6c 69 6f 6e 73 2e 74 6f 70 } 		$a_81_4 = {6e 69 67 67 61 62 6f 77 6e 32 32 6a 61 6e 32 30 32 34 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}