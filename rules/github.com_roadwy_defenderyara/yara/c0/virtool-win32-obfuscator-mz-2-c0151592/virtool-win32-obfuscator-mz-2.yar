rule VirTool_Win32_Obfuscator_MZ_2{
	meta:
		description = "VirTool:Win32/Obfuscator.MZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d c8 8b 45 fc 03 40 3c 8b 40 28 03 45 fc 5b c9 8b f4 83 c6 10 68 00 40 00 00 68 00 10 00 00 51 50 52 c3 } 		$a_01_1 = {c1 c7 07 83 c7 02 03 f8 80 3e 00 75 f2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}