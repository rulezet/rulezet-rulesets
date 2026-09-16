rule VirTool_Win32_CeeInject_gen_GF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 00 07 00 01 00 } 		$a_01_1 = {03 43 28 89 87 b0 00 00 00 } 		$a_01_2 = {8b 87 a4 00 00 00 83 c0 08 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}