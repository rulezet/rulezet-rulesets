rule VirTool_Win32_Obfuscator_AFD{
	meta:
		description = "VirTool:Win32/Obfuscator.AFD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 68 97 c3 0a 00 e8 ?? ?? ff ff 83 c4 0c } 		$a_03_1 = {56 6a 02 5e 39 75 08 72 ?? 53 57 6a 02 5f 8d 1c 36 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}