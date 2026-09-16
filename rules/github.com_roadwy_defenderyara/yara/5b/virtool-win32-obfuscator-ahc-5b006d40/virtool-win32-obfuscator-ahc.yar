rule VirTool_Win32_Obfuscator_AHC{
	meta:
		description = "VirTool:Win32/Obfuscator.AHC,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8f 44 24 24 8d 64 24 08 61 ff e0 } 		$a_01_1 = {2c 45 c0 c0 02 87 d2 87 d2 aa 8a ed d0 c4 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}