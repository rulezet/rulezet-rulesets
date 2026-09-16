rule VirTool_Win32_VBInject_AEU{
	meta:
		description = "VirTool:Win32/VBInject.AEU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 4b 61 6b 61 62 61 5c 55 6e 77 65 6c 6c 5c 54 72 69 6d 6d 69 6e 67 73 5c 49 6b 61 6c 65 5c 56 42 36 2e 4f 4c 42 } 		$a_01_1 = {4d 65 74 61 6d 6f 72 70 68 6f 75 73 30 } 		$a_01_2 = {48 75 73 62 61 6e 64 6c 65 73 73 36 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}