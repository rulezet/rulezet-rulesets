rule VirTool_Win32_Obfuscator_AKI{
	meta:
		description = "VirTool:Win32/Obfuscator.AKI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 8c 0e c0 08 00 00 88 4c 02 11 8b 55 ?? 83 c2 01 89 55 90 1b 00 eb } 		$a_03_1 = {3b 91 bc 08 00 00 0f 83 9c 00 00 00 8b 45 ?? 03 45 ?? 33 c9 8a 88 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}