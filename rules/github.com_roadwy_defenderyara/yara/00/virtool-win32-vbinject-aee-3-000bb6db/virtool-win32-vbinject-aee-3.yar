rule VirTool_Win32_VBInject_AEE_3{
	meta:
		description = "VirTool:Win32/VBInject.AEE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff c5 f1 44 00 c7 85 ?? ?? ff ff 01 00 00 00 83 65 ?? 00 eb 0c 8b 45 ?? 03 85 ?? ?? ff ff 89 45 ?? 8b 45 ?? 3b 85 ?? ?? ff ff 0f 8f ?? ?? 00 00 d9 e8 51 51 dd 1c 24 e8 90 09 04 00 c7 85 } 		$a_03_1 = {dd 58 34 d9 e8 51 51 dd 1c 24 e8 ?? ?? ?? ?? 8b 45 08 dd 58 34 d9 e8 51 51 dd 1c 24 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}