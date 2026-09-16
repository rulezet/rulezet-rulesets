rule VirTool_Win32_VBInject_gen_CE_2{
	meta:
		description = "VirTool:Win32/VBInject.gen!CE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d0 33 c0 8a 04 13 8b 55 00 8a 0c 08 8b 42 0c 8b 72 14 8b 15 ?? ?? ?? ?? 2b c6 88 0d ?? ?? ?? ?? 03 d0 8a 1a 32 d9 88 1a 8b 0d ?? ?? ?? ?? 41 3b cf 89 0d ?? ?? ?? ?? 0f 8e ?? ff ff ff } 		$a_03_1 = {52 ff d7 6a 47 8d 85 ?? ?? ff ff 50 ff d7 6a 6f 8d 8d ?? ?? ff ff 51 ff d7 6a 54 8d 95 ?? ?? ff ff 52 ff d7 6a 6f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}