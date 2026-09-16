rule VirTool_Win32_Obfuscator_BZN{
	meta:
		description = "VirTool:Win32/Obfuscator.BZN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 83 c4 04 50 56 03 f0 4e 8a 0e 5e 58 4b c0 c1 02 80 c1 f9 8a d0 fe ca 80 e2 01 32 ca 80 f1 03 81 e1 ff 00 00 00 80 64 06 ff 00 } 		$a_03_1 = {77 b5 7f b3 7e b1 61 e9 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? ff d6 } 		$a_01_2 = {3d 00 00 09 00 0f 87 2f 00 00 00 ba 00 50 02 00 3b c2 0f } 		$a_01_3 = {81 c6 f4 da ff ff ff d6 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}