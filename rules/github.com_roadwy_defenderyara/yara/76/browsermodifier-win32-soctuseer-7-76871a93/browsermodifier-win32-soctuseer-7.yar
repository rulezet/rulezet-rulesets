rule BrowserModifier_Win32_Soctuseer_7{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 } 		$a_03_1 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d [0-06] 5c 73 72 63 5c 68 74 74 70 5f 69 6e 74 65 72 63 65 70 74 69 6f 6e 5c 90 05 10 04 30 2d 39 5f 2e 70 64 62 } 		$a_01_2 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 63 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}