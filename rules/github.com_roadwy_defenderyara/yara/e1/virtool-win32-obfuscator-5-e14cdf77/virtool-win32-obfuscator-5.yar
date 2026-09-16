rule VirTool_Win32_Obfuscator_5{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {94 8b 52 0c 8a 14 1a 8a 1c } 		$a_01_1 = {75 23 8b 51 14 8b 41 10 8b fb 2b fe 0f 80 } 		$a_01_2 = {ff 74 27 2b fe 8d 95 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}