rule VirTool_Win32_Obfuscator_BL_3{
	meta:
		description = "VirTool:Win32/Obfuscator.BL,SIGNATURE_TYPE_PEHSTR,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 8b 05 30 00 00 00 89 45 fc 8b 45 fc 83 c0 0c 8b 00 83 c0 0c 8b 00 83 c0 18 8b 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}