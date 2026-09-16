rule VirTool_Win32_Obfuscator_AKG{
	meta:
		description = "VirTool:Win32/Obfuscator.AKG,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 89 45 e4 58 8b 45 e4 83 78 64 02 73 07 33 c0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}