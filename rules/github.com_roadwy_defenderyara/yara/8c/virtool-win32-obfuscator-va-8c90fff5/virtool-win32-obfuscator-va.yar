rule VirTool_Win32_Obfuscator_VA{
	meta:
		description = "VirTool:Win32/Obfuscator.VA,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 f8 00 83 e8 2d ff e0 cc cc cc cc cc } 		$a_01_1 = {8b 95 f0 fd ff ff 8a 0c 4a 88 8c 28 e0 fc ff ff } 		$a_00_2 = {68 65 6c 70 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}