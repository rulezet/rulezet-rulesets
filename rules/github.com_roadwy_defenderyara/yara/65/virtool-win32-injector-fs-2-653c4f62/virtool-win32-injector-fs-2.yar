rule VirTool_Win32_Injector_FS_2{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {56 4d 50 72 6f 74 65 63 74 [0-10] 00 b0 04 00 } 		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } 		$a_01_2 = {6c 61 75 6e 63 68 00 } 		$a_01_3 = {43 6f 6e 66 69 67 2e 69 6e 69 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=16
 
}