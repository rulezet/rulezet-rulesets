rule VirTool_Win32_CeeInject_gen_KC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 00 00 ba 30 75 00 00 e8 90 09 02 00 b9 } 		$a_03_1 = {6a 40 68 00 30 00 00 68 ?? 61 00 00 6a 00 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}