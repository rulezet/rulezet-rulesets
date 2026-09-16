rule Backdoor_Win32_AgentTesla_B_{
	meta:
		description = "Backdoor:Win32/AgentTesla.B!!AgentTesla.B,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 63 61 6d 5f 6c 69 6e 6b 3d } 		$a_01_1 = {73 63 72 65 65 6e 5f 6c 69 6e 6b 3d } 		$a_01_2 = {73 69 74 65 5f 75 73 65 72 6e 61 6d 65 3d } 		$a_01_3 = {70 63 6e 61 6d 65 3d } 		$a_01_4 = {6c 6f 67 64 61 74 61 3d } 		$a_01_5 = {73 63 72 65 65 6e 3d } 		$a_01_6 = {69 70 61 64 64 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}