rule VirTool_Win32_Obfuscator_ADB_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ADB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {8e 72 19 a6 } 		$a_01_1 = {9a 35 61 d5 } 		$a_01_2 = {b9 e9 00 00 00 39 c8 75 } 		$a_01_3 = {bb e9 00 00 00 be 05 00 00 00 } 		$a_01_4 = {b8 e9 00 00 00 39 c1 75 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}