rule VirTool_Win32_Obfuscator_VC_4{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 f7 57 06 f2 e9 } 		$a_01_1 = {68 ce 8a 23 69 e9 } 		$a_01_2 = {68 8f b0 e9 11 e9 } 		$a_01_3 = {68 60 d8 0d da e9 } 		$a_01_4 = {68 d6 25 22 cb e9 } 		$a_01_5 = {81 f9 b1 6b 89 31 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}