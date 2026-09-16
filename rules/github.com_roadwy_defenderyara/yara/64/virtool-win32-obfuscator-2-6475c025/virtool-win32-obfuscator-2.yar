rule VirTool_Win32_Obfuscator_2{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 69 c0 01 01 00 00 50 e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}