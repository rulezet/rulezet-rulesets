rule VirTool_Win32_Obfuscator{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d c0 2b 4d c0 89 4d c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}