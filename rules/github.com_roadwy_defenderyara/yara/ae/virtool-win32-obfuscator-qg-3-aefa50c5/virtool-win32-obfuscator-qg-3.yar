rule VirTool_Win32_Obfuscator_QG_3{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 57 e7 67 5e 12 12 aa a3 17 13 0e e8 39 17 f7 57 1c 1c d2 } 		$a_01_1 = {25 5e e8 86 39 53 0c 1e e7 15 f5 72 31 53 22 2b 15 13 4a 78 } 		$a_01_2 = {e4 96 78 33 15 3a 27 15 1a b2 fe 07 15 0e 06 3d 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}