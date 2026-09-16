rule VirTool_Win32_Obfuscator_YE_2{
	meta:
		description = "VirTool:Win32/Obfuscator.YE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 05 14 81 40 00 eb 26 00 00 a0 93 94 40 00 c7 05 ce 8b 40 00 9a 08 00 00 3c 25 0f 84 11 00 00 00 0f b7 05 8a 8b 40 00 b8 ff 00 00 00 e9 b9 01 00 00 } 		$a_01_1 = {c7 05 00 81 40 00 77 38 00 00 a0 93 94 40 00 3c 25 0f 84 14 00 00 00 b8 ff 00 00 00 c7 05 04 81 40 00 9a 24 00 00 e9 dc 00 00 00 } 		$a_01_2 = {a0 93 94 40 00 c7 05 08 81 40 00 97 79 00 00 3c 25 0f 84 0f 00 00 00 b8 a5 0e 00 00 b8 ff 00 00 00 e9 8e 01 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}