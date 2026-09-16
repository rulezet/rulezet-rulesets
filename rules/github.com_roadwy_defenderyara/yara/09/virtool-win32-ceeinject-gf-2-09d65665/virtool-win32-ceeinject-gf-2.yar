rule VirTool_Win32_CeeInject_GF_2{
	meta:
		description = "VirTool:Win32/CeeInject.GF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 85 c8 fd ff ff 8b 0d ?? ?? ?? 00 51 ff 15 ?? ?? ?? 00 83 c4 04 8b 55 f4 } 		$a_03_1 = {00 03 95 58 ff ff ff 88 0a 8b 85 bc fe ff ff 83 e0 d2 0f b6 4d f2 0f b7 95 40 ff ff ff 2b ca 0b c1 88 85 2f ff ff ff 0f b7 85 08 ff ff ff b9 26 00 00 00 90 09 05 00 8b 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}