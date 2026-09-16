rule VirTool_Win32_Obfuscator_PN_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8d 6c 24 ?? 81 ec } 		$a_03_1 = {8d 7e 14 8b 37 8b d8 eb 90 14 3b f7 75 ?? 33 c0 5f 5b 5e c9 c2 04 00 8b 46 10 eb f4 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}