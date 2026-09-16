rule VirTool_Win32_Obfuscator_UG_2{
	meta:
		description = "VirTool:Win32/Obfuscator.UG,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_09_0 = {ff 56 04 85 c0 75 57 60 8b 7d ec 57 03 7d e8 b0 68 aa 8b 45 fc ab b0 c3 aa 8b 4d e4 5e 8b 7d e0 f3 a4 61 8b 45 d4 50 8b 07 50 ff 56 08 } 		$a_09_1 = {60 8b 4d fc 8b 75 f8 8b 7d f4 ad 89 c2 51 c1 e9 02 ad 31 d0 ab e2 fa 59 83 e1 03 83 f9 00 74 06 ac 32 c2 aa e2 fa 61 } 	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1) >=2
 
}