rule VirTool_Win32_Obfuscator_PX{
	meta:
		description = "VirTool:Win32/Obfuscator.PX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 6b 59 6f 06 50 e8 } 		$a_03_1 = {8d 70 54 6a 04 50 8d 80 ?? ?? ?? ?? 51 91 90 09 07 00 59 8b 85 ?? f4 ff } 		$a_03_2 = {56 57 64 8b 35 18 00 00 00 8d 76 30 6a 04 50 8d 80 ?? ?? ?? ?? 51 91 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}