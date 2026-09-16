rule Trojan_BAT_AgentTesla_M_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_02_0 = {01 57 15 02 08 09 01 ?? ?? ?? fa 01 33 00 16 00 00 01 ?? ?? ?? 2a ?? ?? ?? 06 ?? ?? ?? 03 ?? ?? ?? 0e } 		$a_81_1 = {5a 6c 61 66 6d } 		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 		$a_81_3 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } 		$a_81_4 = {47 65 74 44 6f 6d 61 69 6e } 	condition:
		((#a_02_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}