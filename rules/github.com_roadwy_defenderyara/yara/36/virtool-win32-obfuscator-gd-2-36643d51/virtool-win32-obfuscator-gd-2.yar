rule VirTool_Win32_Obfuscator_GD_2{
	meta:
		description = "VirTool:Win32/Obfuscator.GD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 1b 00 00 00 ?? 8b 4c 24 0c 8b 81 a8 00 00 00 89 81 a0 00 00 00 83 81 b8 00 00 00 07 33 c0 c3 33 c0 ff 04 24 64 ff 30 64 89 20 cc e8 3c 00 00 00 } 		$a_03_1 = {e8 1d 00 00 00 8b 4c 24 0c 8b 91 b0 00 00 00 4a 75 07 83 81 b8 00 00 00 03 89 91 b0 00 00 00 33 c0 c3 33 c9 64 ff 31 64 89 21 ?? 11 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}