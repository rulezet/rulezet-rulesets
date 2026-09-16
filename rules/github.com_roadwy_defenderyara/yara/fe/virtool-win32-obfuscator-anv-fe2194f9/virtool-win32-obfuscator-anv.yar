rule VirTool_Win32_Obfuscator_ANV{
	meta:
		description = "VirTool:Win32/Obfuscator.ANV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 d3 80 fa ?? 88 94 34 ?? ?? 00 00 73 09 fe ca 88 94 34 ?? ?? 00 00 46 } 		$a_03_1 = {df e0 f6 c4 41 75 16 68 ?? ?? ?? ?? 6a 00 8d 94 24 ?? ?? 00 00 ff d2 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}