rule VirTool_Win32_Obfuscator_BZN_2{
	meta:
		description = "VirTool:Win32/Obfuscator.BZN,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 00 2f 2f 2f 2f 05 04 00 00 00 c7 00 2f 2f 2f 2f 05 04 00 00 00 c7 00 77 73 65 63 05 04 00 00 00 c7 00 65 64 69 74 } 		$a_01_1 = {8a 06 5e 59 4a 04 f9 8a d9 fe cb d1 cb 81 e3 00 00 00 a0 d1 c3 32 c3 34 f6 88 44 0e ff 83 e9 01 83 f9 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}