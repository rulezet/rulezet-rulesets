rule Trojan_BAT_AgentTesla_MB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {45 6d 61 69 6c 20 43 68 65 63 6b 65 72 20 50 72 6f } 		$a_81_1 = {55 4c 45 73 65 } 		$a_81_2 = {64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } 		$a_81_3 = {33 74 67 5f 78 73 67 } 		$a_81_4 = {71 66 61 2f 74 69 5f 30 74 69 5f } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}