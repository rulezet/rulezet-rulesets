rule VirTool_Win32_CeeInject_GF{
	meta:
		description = "VirTool:Win32/CeeInject.GF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 38 e9 75 0b ba ff ff 00 00 66 39 50 03 74 07 40 41 83 f9 1e 7c e9 80 38 e9 } 		$a_01_1 = {c7 44 24 64 a9 dd e5 62 c7 44 24 68 86 00 c2 1b 8b 74 24 10 8d 74 b4 38 ff 36 57 e8 } 		$a_01_2 = {c7 84 3d e0 fe ff ff 2e 64 6c 6c c6 84 3d e4 fe ff ff 00 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}