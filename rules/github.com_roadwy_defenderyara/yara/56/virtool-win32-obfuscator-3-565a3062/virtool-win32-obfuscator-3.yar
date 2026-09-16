rule VirTool_Win32_Obfuscator_3{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}