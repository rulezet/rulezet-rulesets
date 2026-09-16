rule VirTool_Win32_Obfuscator_AEP{
	meta:
		description = "VirTool:Win32/Obfuscator.AEP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 00 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 83 c4 0c 68 00 00 00 00 } 		$a_01_1 = {68 f0 a1 81 51 e8 76 1c 00 00 dd d8 } 		$a_01_2 = {68 9f 21 c2 5f e8 66 3a 00 00 dd d8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}