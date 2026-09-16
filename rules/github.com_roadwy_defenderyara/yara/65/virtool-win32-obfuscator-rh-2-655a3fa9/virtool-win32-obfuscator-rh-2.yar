rule VirTool_Win32_Obfuscator_RH_2{
	meta:
		description = "VirTool:Win32/Obfuscator.RH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 00 48 00 47 00 46 00 4a 00 48 00 47 00 48 00 00 00 } 		$a_01_1 = {8b 44 24 14 33 c6 03 c7 89 44 24 20 89 4c 24 } 		$a_03_2 = {8b 4c 24 1c 33 c6 03 c7 3b c8 0f 84 ?? 00 00 00 ff 74 24 1c } 		$a_01_3 = {2d 90 03 01 01 3a 38 31 02 41 83 f9 09 0f 82 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}