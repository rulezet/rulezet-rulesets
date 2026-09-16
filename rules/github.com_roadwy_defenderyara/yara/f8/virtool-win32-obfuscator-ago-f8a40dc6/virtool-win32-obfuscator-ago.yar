rule VirTool_Win32_Obfuscator_AGO{
	meta:
		description = "VirTool:Win32/Obfuscator.AGO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {60 33 db 8d bb 00 b1 6c 00 b9 } 		$a_03_1 = {2b db 33 d2 b9 00 00 00 00 60 61 8d bb 00 b1 6b 00 57 be 00 00 00 00 b9 f0 ff 8f 00 bb ?? ?? ?? ?? 03 f3 60 f3 a4 61 } 		$a_03_2 = {8a 06 88 07 46 47 49 eb ?? 33 db 8d bb 00 b1 6b 00 b9 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}