rule VirTool_Win32_VBInject_gen_JD{
	meta:
		description = "VirTool:Win32/VBInject.gen!JD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 04 f2 89 4c f2 04 b8 ?? ?? ?? ?? f7 d8 b9 ?? ?? ?? ?? 83 d1 00 f7 d9 8b 15 ?? ?? ?? ?? 6a ?? 5e 2b 72 14 8b 15 ?? ?? ?? ?? 8b 52 0c 89 04 f2 89 4c f2 04 } 		$a_03_1 = {2b 48 14 a1 ?? ?? ?? ?? 8b 40 0c c7 04 c8 ?? ?? ?? ?? c7 44 c8 04 } 		$a_03_2 = {b8 04 07 00 00 8b 3c 24 [0-40] 83 e8 04 0f 6e 07 0f 6e ce 0f ef c1 0f 7e 07 83 c7 04 85 c0 75 ea c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=2
 
}