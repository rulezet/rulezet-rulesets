rule VirTool_Win32_Obfuscator_BZN_3{
	meta:
		description = "VirTool:Win32/Obfuscator.BZN,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 00 2f 73 79 73 05 04 00 00 00 c7 00 75 65 6d 34 81 28 01 00 00 01 05 04 00 00 00 c7 00 32 2f 77 73 05 04 00 00 00 c7 00 65 63 65 64 } 		$a_01_1 = {8a 0e 5e 58 4b c0 c1 02 80 c1 f9 8a d0 fe ca 80 e2 01 32 ca 80 f1 03 88 4c 06 ff 2d 01 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}