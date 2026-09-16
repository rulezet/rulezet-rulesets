rule VirTool_Win32_Obfuscator_ADB_3{
	meta:
		description = "VirTool:Win32/Obfuscator.ADB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 70 65 2f 52 65 76 65 74 6f 6e 2e 46 42 } 		$a_01_1 = {63 6f 6d 6d 75 6e 69 74 79 61 68 6f 75 73 65 2e 70 64 62 } 		$a_01_2 = {68 6f 75 72 34 68 6f 75 73 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}