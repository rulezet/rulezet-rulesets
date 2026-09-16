rule VirTool_Win32_CeeInject_M_7{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR,63 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 41 6e 74 69 41 6e 74 69 56 69 72 75 73 5f 63 6f 6d 6d 61 6e 64 } 		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 } 		$a_01_2 = {4e 65 77 20 45 58 45 20 69 6d 61 67 65 20 69 6e 6a 65 63 74 65 64 20 69 6e 74 6f 20 70 72 6f 63 65 73 73 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}