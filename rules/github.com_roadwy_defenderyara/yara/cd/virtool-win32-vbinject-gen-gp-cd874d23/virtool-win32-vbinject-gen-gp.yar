rule VirTool_Win32_VBInject_gen_GP{
	meta:
		description = "VirTool:Win32/VBInject.gen!GP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 01 07 00 01 00 } 		$a_01_1 = {68 95 e3 35 69 } 		$a_01_2 = {89 90 b0 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}