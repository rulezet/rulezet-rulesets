rule VirTool_Win32_CeeInject_M{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 65 00 2e 00 64 00 6c 00 6c 00 00 00 } 		$a_01_1 = {6c 00 7a 00 2e 00 64 00 6c 00 6c 00 00 00 } 		$a_03_2 = {45 78 65 63 75 74 65 46 69 6c 65 00 44 61 74 61 00 [0-10] 4c 7a 6d 61 55 6e 63 6f 6d 70 72 65 73 73 00 } 		$a_01_3 = {2e 53 74 6f 6e 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}