rule VirTool_Win32_Obfuscator_4{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 68 3e 8b 00 83 f8 70 74 90 09 06 00 64 a1 30 00 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}