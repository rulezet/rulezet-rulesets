rule VirTool_Win32_DelfInject_gen_CF{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 ff 30 64 89 20 33 c0 89 45 f8 8b f3 66 81 3e 4d 5a 0f 85 ?? ?? ?? ?? 8b fb 03 7e 3c 81 3f 50 45 00 00 } 		$a_01_1 = {68 f8 00 00 00 57 8b c3 03 46 3c 50 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}