rule VirTool_Win32_Injector_FZ_3{
	meta:
		description = "VirTool:Win32/Injector.FZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 f8 44 7d 0c 8a 4d ?? 88 0c 02 40 83 f8 44 7c f4 8d 95 ?? ?? ff ff 8b 45 ?? 83 f8 10 } 		$a_03_1 = {8b c8 83 c0 ff 85 c9 75 f1 33 c0 89 45 ?? c7 45 ?? ?? ?? 00 00 } 		$a_03_2 = {be 84 a0 40 00 8d bd ?? ?? ff ff b9 ?? 00 00 00 f3 a5 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}