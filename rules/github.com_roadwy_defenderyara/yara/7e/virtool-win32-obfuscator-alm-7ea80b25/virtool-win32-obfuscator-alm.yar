rule VirTool_Win32_Obfuscator_ALM{
	meta:
		description = "VirTool:Win32/Obfuscator.ALM,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 13 8e c0 09 50 e8 ?? ?? 00 00 8b 4d ?? 68 ee 38 83 0c 51 a3 ?? ?? 40 00 e8 ?? ?? 00 00 68 f2 5d d3 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}