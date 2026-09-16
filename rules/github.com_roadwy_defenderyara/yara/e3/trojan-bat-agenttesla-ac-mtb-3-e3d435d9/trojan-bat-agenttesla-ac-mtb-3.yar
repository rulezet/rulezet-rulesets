rule Trojan_BAT_AgentTesla_AC_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } 		$a_81_1 = {5c 41 75 64 69 6f 41 70 70 } 		$a_81_2 = {2f 43 20 72 75 6e 64 } 		$a_81_3 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c } 		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 54 61 73 6b 41 73 79 6e 63 } 		$a_81_5 = {4a 61 63 6b 2b 4d 79 41 64 64 49 6e 2b 3c 44 6f 77 6e 6c 6f 61 64 3e } 		$a_81_6 = {6a 61 7a 6b 2e 64 6c 6c } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}