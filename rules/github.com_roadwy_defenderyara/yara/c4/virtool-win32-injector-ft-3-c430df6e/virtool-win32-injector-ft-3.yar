rule VirTool_Win32_Injector_FT_3{
	meta:
		description = "VirTool:Win32/Injector.FT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 02 07 00 01 00 8d 8d ?? ?? ff ff 51 ff b5 ?? ?? ff ff ff 55 ?? 89 45 } 		$a_03_1 = {83 c0 34 50 ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff ff 55 ?? 8b 95 ?? ?? ff ff 8b 4a 28 03 8d ?? ?? ff ff 8b 85 ?? ?? ff ff 89 88 b0 00 00 00 } 		$a_01_2 = {6b 65 72 6e 65 6c 33 32 2e 64 56 6c } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}