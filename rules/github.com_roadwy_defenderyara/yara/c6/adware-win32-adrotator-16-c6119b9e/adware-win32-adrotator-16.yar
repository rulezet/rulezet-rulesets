rule Adware_Win32_AdRotator_16{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 72 6f 77 73 65 72 20 65 6e 68 61 6e 63 65 72 } 		$a_01_1 = {61 64 53 70 6f 74 57 6e 64 } 		$a_03_2 = {0f 8c c3 00 00 00 3b 6e f8 0f 8f ba 00 00 00 68 ?? ?? ?? ?? 89 6e f4 57 c6 04 2e 00 ff d3 8b e8 68 ?? ?? ?? ?? 2b ef 57 89 44 24 30 } 		$a_03_3 = {8a 0f 80 f9 28 7c 12 80 f9 7e 7f 0d 8b 1d ?? ?? ?? ?? 0f be c9 8a 4c 19 ?? 88 0a 42 47 48 75 e0 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}