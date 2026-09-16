rule Trojan_BAT_AgentTesla_BB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_00_0 = {01 57 1d b6 09 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 94 00 00 00 28 00 00 00 c3 } 		$a_81_1 = {69 73 50 61 73 73 77 6f 72 64 4d 61 73 6b 65 64 } 		$a_81_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } 		$a_81_3 = {64 69 73 63 6f 72 64 61 70 70 } 		$a_81_4 = {41 70 61 72 74 6d 61 6e 4f 74 6f 2e 70 64 62 } 	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}