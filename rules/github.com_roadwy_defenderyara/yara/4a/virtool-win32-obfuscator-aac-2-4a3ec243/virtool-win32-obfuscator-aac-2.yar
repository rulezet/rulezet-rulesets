rule VirTool_Win32_Obfuscator_AAC_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AAC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 ff 76 50 ff 76 34 ff 55 ?? 85 c0 75 13 6a 40 68 00 30 00 00 ff 76 50 6a 00 ff 55 ?? 85 c0 74 75 89 45 ?? fc 56 8b 4e 54 8b 75 08 8b 7d ?? 33 c0 f3 a4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}