rule VirTool_Win32_VBInject_gen_HT{
	meta:
		description = "VirTool:Win32/VBInject.gen!HT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 04 82 07 00 01 00 } 		$a_01_1 = {03 c2 89 81 b0 00 00 00 } 		$a_01_2 = {3b c2 7f 0e c6 04 07 cc e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}