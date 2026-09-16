rule VirTool_Win32_CeeInject_gen_DR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ff ff 40 3d ?? ?? 00 00 72 e8 } 		$a_03_1 = {8b 49 3c 03 4d 0c 8d 8c 31 f8 00 00 00 89 0d ?? ?? ?? ?? 8b 40 34 8b 51 14 ff 71 10 03 41 0c 03 d6 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}