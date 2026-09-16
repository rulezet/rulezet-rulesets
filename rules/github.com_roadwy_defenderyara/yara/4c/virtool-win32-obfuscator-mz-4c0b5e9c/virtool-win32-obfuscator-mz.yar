rule VirTool_Win32_Obfuscator_MZ{
	meta:
		description = "VirTool:Win32/Obfuscator.MZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 b9 99 99 99 99 50 58 2d 00 01 00 00 05 00 01 00 00 e2 f2 } 		$a_01_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 50 8b c3 33 c0 58 cc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}