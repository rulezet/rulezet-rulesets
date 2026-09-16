rule VirTool_Win32_CeeInject_gen_DZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 ff 73 50 ff 73 34 ff 75 e0 ff ?? ?? 57 } 		$a_02_1 = {8b 40 0c 03 43 34 50 ff ?? ?? ff ?? ?? 0f b7 43 06 ff ?? ?? 83 45 f8 28 39 45 fc 7c c1 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}