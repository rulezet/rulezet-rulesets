rule VirTool_Win32_Obfuscator_AKG_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AKG,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6c 74 68 56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_01_1 = {53 74 6f 72 6d 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}